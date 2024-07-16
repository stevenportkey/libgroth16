#ifndef _GROTH16_H_
#define _GROTH16_H_

/**
 * Verifies the Groth16 proof.
 *
 * @param vk The verification key.
 * @param proving_output The proof output.
 * @return 1 if the proof is valid and 0 if the proof is invalid and negative values if there are errors.
 */
int verify_bn254(const char* vk, const char* proving_output);

/**
 * Loads the context for the circuit.
 * @param wasm_path The path to the WASM file.
 * @param r1cs_path The path to the R1CS file.
 * @param zkey_path The path to the ZKEY file.
 * @note The context should be freed using `free_context_bn254`.
 */
void* load_context_bn254(const char* wasm_path, const char* r1cs_path, const char* zkey_path);

/**
 * Returns the size of the verification key.
 * @param ctx The context that's created using `load_context_bn254`.
 * @return The size of the verification key.
 */
int verifying_key_size_bn254(const void* ctx);

/**
 * Exports the verification key.
 * @param ctx The context that's created using `load_context_bn254`.
 * @param buf The buffer to store the verification key.
 * @param max_len The maximum length of the buffer.
 * @return a positive value if the verification key is exported successfully and negative values if there are errors. The positive value is the size of the verification key.
 */
int export_verifying_key_bn254(const void* ctx, char* buf, int max_len);

/**
 * Proves the input.
 * @param ctx The context that's created using `load_context_bn254`.
 * @param input The input to prove.
 * @param buf The buffer to store the proof.
 * @param max_len The maximum length of the buffer.
 * @return a positive value if the proof is generated successfully and negative values if there are errors. The positive value is the size of the proof.
 */
int prove_bn254(const void* ctx, const char* input, char* buf, int max_len);

/**
 * Frees the context.
 * @param ctx The context that's created using `load_context_bn254`.
 */
void free_context_bn254(void* ctx);

#endif