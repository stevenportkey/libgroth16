use crate::utils::{
    do_prove, do_verify, load_context, ret_or_err, serialize, write_to_buffer, ProvingContext,
};
use std::ffi::CStr;
use crate::returncodes::ReturnCodes;

#[no_mangle]
pub unsafe extern "C" fn verify_bn254(
    vk: *const cty::c_char,
    proving_output: *const cty::c_char,
) -> cty::c_int {
    let vk = unsafe { CStr::from_ptr(vk).to_str() };
    let proving_output = unsafe { CStr::from_ptr(proving_output).to_str() };
    match (vk, proving_output) {
        (Ok(vk), Ok(proving_output)) => match do_verify(vk, proving_output) {
            Ok(true) => ReturnCodes::VerificationSuccess as i32,
            Ok(false) => ReturnCodes::VerificationFailed as i32,
            Err(err) => {
                println!("{}", err);
                ReturnCodes::VerificationFailedWithError as i32
            }
        },
        _ => ReturnCodes::InvalidInput as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn load_context_bn254(
    wasm_path: *const cty::c_char,
    r1cs_path: *const cty::c_char,
    zkey_path: *const cty::c_char,
) -> *mut ProvingContext {
    let wasm_path = unsafe { CStr::from_ptr(wasm_path).to_str() };
    let r1cs_path = unsafe { CStr::from_ptr(r1cs_path).to_str() };
    let zkey_path = unsafe { CStr::from_ptr(zkey_path).to_str() };
    match (wasm_path, r1cs_path, zkey_path) {
        (Ok(wasm_path), Ok(r1cs_path), Ok(zkey_path)) => {
            ret_or_err(load_context(wasm_path, r1cs_path, zkey_path))
        }
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn verifying_key_size_bn254(ctx: Option<&mut ProvingContext>) -> cty::c_int {
    match ctx {
        Some(ctx) => {
            let vk = ctx.verifying_key_in_hex();
            vk.len() as i32
        }
        _ => ReturnCodes::InvalidContext as i32,
    }
}

#[no_mangle]
pub extern "C" fn export_verifying_key_bn254(
    ctx: Option<&mut ProvingContext>,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    match ctx {
        Some(ctx) => {
            let vk = ctx.verifying_key_in_hex();
            write_to_buffer(&vk, buf, max_len)
        }
        _ => ReturnCodes::InvalidContext as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn prove_bn254(
    ctx: Option<&mut ProvingContext>,
    input: *const cty::c_char,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    let input = unsafe { CStr::from_ptr(input).to_str() };
    match (ctx, input) {
        (Some(ctx), Ok(input)) => match do_prove(ctx, input) {
            Ok((pub_inputs, proof)) => match serialize(pub_inputs, proof) {
                Ok(output) => write_to_buffer(&output, buf, max_len),
                Err(_) => ReturnCodes::SerializationFailed as i32,
            },
            Err(_) => ReturnCodes::ProvingFailed as i32,
        },
        (None, _) => ReturnCodes::InvalidContext as i32,
        _ => ReturnCodes::InvalidInput as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_context_bn254(state: *mut ProvingContext) {
    assert!(!state.is_null());
    let _ = Box::from_raw(state); // Rust auto-drops it
}


#[cfg(test)]
mod test {
    use std::str;
    use std::mem;
    use crate::api::*;
    use crate::dto::ProvingOutput;

    fn decode_string(data: &[i8]) -> String {
        let data = data.iter().map(|x| *x as u8).collect::<Vec<u8>>();
        let last_non_zero_index = data.iter().rposition(|&b| b != 0).unwrap_or(0);
        String::from_utf8_lossy(&data[..=last_non_zero_index]).to_string()
    }


    #[test]
    fn test_prove_and_verify_bn254() {
        const BUFFER_SIZE: usize = 1024;
        const VK_LEN: i32 = 592;
        const VK: &str = "67d28bc9637e5842e652e8d19b3c87413c8242b1607c7e738ac2f5d435248d18f68f2792009ed932a3c7f400c2ba7cd9181f331226134fa75dc2cee1e667a3241fca13b5eb1c3b310900c6525fb76657be52dfdf3db1132d0223bee44219a219edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e199b5db8c426b2f2dde0734aa84d0fc9c6ac0b22e89221a030f925eb84996267128258040574d428374aaaaeebb617b4a3f605551973446a56006d973837825ea60200000000000000afcf5144f601ac362d46821e817ebd51e4a25e403862b6796606e18d2b45be0c519f16ffda911e05d663e81541ff4fa1e5eeaf4d2803d9698ad9f967177212a7";

        let mut buffer: Vec<i8> = vec![0; 1024];

        let wasm_path = &*b"testfiles/multiplier2.wasm".iter().map(|&b| b as i8).collect::<Vec<i8>>();
        let r1cs_path = &*b"testfiles/multiplier2.r1cs".iter().map(|&b| b as i8).collect::<Vec<i8>>();
        let zkey_path = &*b"testfiles/multiplier2_0001.zkey".iter().map(|&b| b as i8).collect::<Vec<i8>>();
        unsafe {
            // 0. Load the proving context
            let ctx = load_context_bn254(wasm_path.as_ptr(), r1cs_path.as_ptr(), zkey_path.as_ptr());
            let ctx_ref: &mut ProvingContext = mem::transmute(ctx);

            // 1. Check the verifying key size
            let size = verifying_key_size_bn254(Some(ctx_ref));
            assert_eq!(VK_LEN, size);
            let written_size = export_verifying_key_bn254(Some(ctx_ref), buffer.as_mut_ptr(), BUFFER_SIZE as i32);
            assert_eq!(VK, decode_string(buffer.as_slice()));
            assert_eq!(VK_LEN, written_size);

            // 2. Prove
            let input = &*b"{\"a\": [\"12\"], \"b\": [\"3\"]}\0".iter().map(|&b| b as i8).collect::<Vec<i8>>();
            let res = prove_bn254(Some(ctx_ref), input.as_ptr(), buffer.as_mut_ptr(), BUFFER_SIZE as i32);
            assert!(res >= 0);
            let output = decode_string(buffer.as_slice());
            let output = serde_json::from_str::<ProvingOutput>(&output);
            assert!(output.is_ok());
            assert_eq!(vec!["36"], output.as_ref().unwrap().public_inputs);

            // 3. Verify
            let result = verify_bn254(VK.bytes().map(|x| x as i8).collect::<Vec<_>>().as_ptr(), buffer.as_ptr());
            assert_eq!(1, result);

            free_context_bn254(ctx);
        }
    }
}