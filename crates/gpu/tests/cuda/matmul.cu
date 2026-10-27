// GPU-2（TASK-127.6・#552）の CUDA ワークロード参照実装。FP32 の行列積 C = A x B を GPU で計算する。
//
// 呼び出し元: crates/gpu/tests/cuda_workload.rs の内側（新しい PID / mount / UTS / IPC namespace に入り、
// CDI の deviceNodes・mounts・hooks・env を当てて pivot_root した後の PID 1）が、本バイナリを起動する。
// 契約:
//   argv   = <n> <a_path> <b_path> <c_path>   n は 64 の倍数（64..=8192）
//   入出力 = 行優先・リトルエンディアンの raw f32（n * n 要素）。入力は長さが n * n * 4 と一致すること
//   stdout = `cuda_device=<GPU 名>` の行（GPU で実行した記録）。成功時の終了コードは 0、失敗時は非 0
// 正否の判定（CPU 参照値との相対誤差）は試験側が行う。本バイナリの自己申告は信用されない。
//
// ビルド（rootfs の glibc と互換のある環境で。cudart は静的リンク、libcuda.so.1 は CDI の mounts が供給する）:
//   nvcc -O2 -o cuda-matmul matmul.cu
// 出来たバイナリを rootfs の雛形へ置き、その rootfs 内の絶対パスを試験の環境変数で渡す。
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cuda_runtime.h>

#define TILE 16

#define CHECK(call)                                                          \
    do {                                                                     \
        cudaError_t e_ = (call);                                             \
        if (e_ != cudaSuccess) {                                             \
            fprintf(stderr, "cuda error: %s\n", cudaGetErrorString(e_));     \
            return 1;                                                        \
        }                                                                    \
    } while (0)

__global__ void matmul(const float *a, const float *b, float *c, int n) {
    __shared__ float ta[TILE][TILE];
    __shared__ float tb[TILE][TILE];
    int row = blockIdx.y * TILE + threadIdx.y;
    int col = blockIdx.x * TILE + threadIdx.x;
    float acc = 0.0f;
    for (int t = 0; t < n / TILE; ++t) {
        ta[threadIdx.y][threadIdx.x] = a[row * n + t * TILE + threadIdx.x];
        tb[threadIdx.y][threadIdx.x] = b[(t * TILE + threadIdx.y) * n + col];
        __syncthreads();
        for (int k = 0; k < TILE; ++k) acc += ta[threadIdx.y][k] * tb[k][threadIdx.x];
        __syncthreads();
    }
    c[row * n + col] = acc;
}

static bool read_all(const char *path, std::vector<float> &out, size_t count) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    out.resize(count);
    size_t got = fread(out.data(), sizeof(float), count, f);
    int extra = fgetc(f);
    fclose(f);
    return got == count && extra == EOF;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <n> <a> <b> <c>\n", argv[0]);
        return 2;
    }
    char *end = nullptr;
    long n = strtol(argv[1], &end, 10);
    if (*end != '\0' || n < 64 || n > 8192 || n % 64 != 0) {
        fprintf(stderr, "invalid n\n");
        return 2;
    }
    size_t count = (size_t)n * (size_t)n;
    std::vector<float> ha, hb, hc(count);
    if (!read_all(argv[2], ha, count) || !read_all(argv[3], hb, count)) {
        fprintf(stderr, "failed to read inputs\n");
        return 2;
    }
    cudaDeviceProp prop;
    CHECK(cudaGetDeviceProperties(&prop, 0));
    printf("cuda_device=%s\n", prop.name);
    fflush(stdout);
    float *da = nullptr, *db = nullptr, *dc = nullptr;
    size_t bytes = count * sizeof(float);
    CHECK(cudaMalloc(&da, bytes));
    CHECK(cudaMalloc(&db, bytes));
    CHECK(cudaMalloc(&dc, bytes));
    CHECK(cudaMemcpy(da, ha.data(), bytes, cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(db, hb.data(), bytes, cudaMemcpyHostToDevice));
    dim3 block(TILE, TILE), grid(n / TILE, n / TILE);
    matmul<<<grid, block>>>(da, db, dc, (int)n);
    CHECK(cudaGetLastError());
    CHECK(cudaDeviceSynchronize());
    CHECK(cudaMemcpy(hc.data(), dc, bytes, cudaMemcpyDeviceToHost));
    cudaFree(da);
    cudaFree(db);
    cudaFree(dc);
    FILE *f = fopen(argv[4], "wb");
    if (!f || fwrite(hc.data(), sizeof(float), count, f) != count || fclose(f) != 0) {
        fprintf(stderr, "failed to write output\n");
        return 1;
    }
    return 0;
}
