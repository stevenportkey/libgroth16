# libgroth16

This library is a wrapper of the rust implementation of the [ark-groth16](https://crates.io/crates/ark-groth16) crate. It allows other language to make use of the library.

The API:

```C
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
```

## Example


For the `Multiplier2` circuit like below:
```circom
pragma circom 2.0.0;

template Multiplier2 () {  

   signal input a;  
   signal input b;  
   signal output c;  

   c <== a * b;  
}

component main = Multiplier2();  
```

Below is an example of Proving Input where the keys are the input names and values are array of integers represented in decimal string format:
```json
{"a": ["12"], "b": ["3"]}
```

And an example of Proving Output is:
```json
{
    "public_inputs": [
        "36"
    ],
    "proof": {
        "pi_a": [
            "11980995157706750775102298714225901939162272638792690932503267396728742698482",
            "11145854692571799789992177601488093235130300759507117738557712035982354916831",
            "1"
        ],
        "pi_b": [
            [
                "2687710753206845800910431925926757673764523108435569745944635552368858038481",
                "12512373346760772175623499841115749275991450622438636099193268082915917011340"
            ],
            [
                "18754787628114428026691637038965318802602391559721937573339672676432783894132",
                "13023056232653065177699674052761357188469500459563823625872509885513646959163"
            ],
            [
                "1",
                "0"
            ]
        ],
        "pi_c": [
            "19735114149139884807748407125374579541576687107117354234983731772228418061647",
            "5277013802739589131917868726823928903247450079141074937424124486173721787478",
            "1"
        ],
        "protocol": "groth16"
    }
}
```
