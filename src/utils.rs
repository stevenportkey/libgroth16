use crate::dto::ProvingOutput;
use anyhow::Context;
use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ec::pairing::Pairing;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use num_bigint::BigInt;
use num_traits::Num;
use rand::thread_rng;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
// use eyre::ContextCompat;
use ark_ff::PrimeField;

pub struct ProvingContext {
    pub(crate) cfg: CircomConfig<Bn254>,
    pub(crate) pk: ProvingKey<Bn254>,
}

impl ProvingContext {
    pub(crate) fn verifying_key_in_hex(&self) -> String {
        let mut vk = Vec::new();
        self.pk
            .vk
            .serialize_compressed(&mut vk)
            .expect("failed to serialize the verifying key");
        hex::encode(vk)
    }
}

#[derive(Debug)]
struct InvalidPathError;

impl Display for InvalidPathError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "path is not valid")
    }
}

impl std::error::Error for InvalidPathError {}

#[derive(Debug)]
struct BuildError;

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "path is not valid")
    }
}

impl std::error::Error for BuildError {}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl Display for crate::utils::ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParseError: {}", self.message)
    }
}

impl std::error::Error for crate::utils::ParseError {}

pub(crate) fn to_vec(vk: *const cty::c_char, vk_len: cty::c_int) -> Vec<u8> {
    unsafe {
        let mut res = Vec::new();
        for i in 0..vk_len {
            let byte = *vk.offset(i as isize);
            res.push(byte as u8);
        }
        res
    }
}

pub(crate) fn parse_input(
    input: *const cty::c_char,
    input_len: cty::c_int,
) -> anyhow::Result<Vec<<Bn254 as Pairing>::ScalarField>> {
    let mut inputs_vec = Vec::new();

    for i in 0..((input_len / 32) as isize) {
        let scalar_vec = unsafe { to_vec(input.offset(i * 32), 32) };
        let scalar = <Bn254 as Pairing>::ScalarField::deserialize_compressed(&*scalar_vec)?;
        inputs_vec.push(scalar);
    }
    Ok(inputs_vec)
}

pub(crate) fn do_verify(vk: &str, proving_output: &str) -> anyhow::Result<bool> {
    let vk = hex::decode(vk).context("failed to decode VerifyingKey")?;
    let proving_output: ProvingOutput =
        serde_json::from_str(proving_output).context("failed to decode ProvingOutput")?;
    let proof = proving_output.proof.into();
    let inputs = decode_public_input_array(proving_output.public_inputs)?;
    do_verify0(vk, proof, inputs)
}

pub(crate) fn do_verify0(
    vk: Vec<u8>,
    proof: Proof<Bn254>,
    inputs: Vec<<Bn254 as Pairing>::ScalarField>,
) -> anyhow::Result<bool> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&*vk)?;
    let pvk = prepare_verifying_key(&vk);
    let res = Groth16::<Bn254>::verify_with_processed_vk(&pvk, inputs.as_slice(), &proof)?;
    Ok(res)
}

pub(crate) fn decode_public_input_array(
    public_inputs: Vec<String>,
) -> anyhow::Result<Vec<<Bn254 as Pairing>::ScalarField>> {
    let inputs: Vec<_> = public_inputs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let value = BigInt::from_str_radix(s, 10).map_err(|_| ParseError {
                message: format!("{}: {}", i, s),
            })?;
            let (_, bytes) = value.to_bytes_be();
            let scalar = <Bn254 as Pairing>::ScalarField::from_be_bytes_mod_order(bytes.as_slice());
            Ok::<<Bn254 as Pairing>::ScalarField, ParseError>(scalar)
        })
        .collect();
    let _ = match inputs.iter().any(|value| value.is_err()) {
        true => Ok(0),
        false => Err(ParseError {
            message: "parse error".to_string(),
        }),
    }
        .context("failed to parse input");

    let inputs = inputs
        .iter()
        .map(|value| *value.as_ref().unwrap())
        .collect();
    Ok(inputs)
}

pub(crate) fn load_context(
    wasm_path: &str,
    r1cs_path: &str,
    zkey_path: &str,
) -> anyhow::Result<ProvingContext> {
    let cfg = CircomConfig::new(wasm_path, r1cs_path)
        .map_err(|_| InvalidPathError)
        .context("invalid wasm or r1cs file path")?;
    let mut zkey_file = File::open(zkey_path).context("invalid zkey file")?;
    let (pk, _) = read_zkey(&mut zkey_file).context("failed to load zkey")?;
    Ok(ProvingContext { cfg, pk })
}

pub(crate) fn ret_or_err<T, E>(res: Result<T, E>) -> *mut T
    where
        E: Debug + Display,
{
    match res {
        Ok(res) => Box::into_raw(Box::new(res)),
        Err(_e) => std::ptr::null_mut(),
    }
}

fn parse_proving_input(input: &str) -> anyhow::Result<HashMap<String, Vec<BigInt>>> {
    let input: HashMap<String, Vec<String>> =
        serde_json::from_str(input).context("failed to parse JSON")?;

    let mut parsed_input = HashMap::new();

    for (key, values) in input {
        let converted_values: Vec<BigInt> = values
            .into_iter()
            .map(|s| BigInt::from_str_radix(&s, 10).unwrap_or_else(|_| BigInt::from(0)))
            .collect();

        parsed_input.insert(key, converted_values);
    }

    Ok(parsed_input)
}

pub(crate) fn do_prove(
    ctx: &ProvingContext,
    input: &str,
) -> anyhow::Result<(Vec<<Bn254 as Pairing>::ScalarField>, Proof<Bn254>)> {
    let input = parse_proving_input(input).context("failed to parse input")?;
    let mut builder = CircomBuilder::new(ctx.cfg.clone());
    for (key, value) in input.iter() {
        for item in value {
            builder.push_input(key, item.clone());
        }
    }

    let circom = builder
        .build()
        .map_err(|_| BuildError)
        .context("failed to build circuit")?;

    let pub_inputs = circom
        .get_public_inputs()
        .context("failed to get public inputs")?;

    let mut rng = thread_rng();

    let cs = ConstraintSystem::<<Bn254 as Pairing>::ScalarField>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(is_satisfied);

    let proof = Groth16::<Bn254, CircomReduction>::prove(&ctx.pk, circom, &mut rng)
        .context("failed to produce proof")?;

    Ok((pub_inputs, proof))
}

pub(crate) fn write_to_buffer(
    output: &String,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    let src = output.as_bytes().as_ptr();
    let len = output.as_bytes().len();
    let len_c_int = len as cty::c_int;
    if len_c_int <= max_len - 1 {
        unsafe {
            std::ptr::copy(src, buf as *mut u8, len);
            (*buf.add(len)) = 0;
        }
        len_c_int
    } else {
        println!("required length is {}", len_c_int);
        -1000
    }
}

pub(crate) fn serialize(
    public_inputs: Vec<<Bn254 as Pairing>::ScalarField>,
    proof: Proof<Bn254>,
) -> anyhow::Result<String> {
    let output = ProvingOutput {
        public_inputs: public_inputs.iter().map(|v| v.to_string()).collect(),
        proof: proof.into(),
    };
    let output = serde_json::to_string(&output).expect("failed to serialize to output");
    Ok(output)
}

#[cfg(test)]
mod utils_test {
    use crate::utils::{do_prove, do_verify, load_context, parse_proving_input, serialize};
    use itertools::Itertools;

    #[test]
    fn test_parse_proving_input() {
        let json_str = r#"
            {
                "key1": ["123", "456"],
                "key2": [
                    "5841544268561861499519250994748571",
                    "282086110796185156675799806248152448"
                ]
            }
        "#;

        let parsed_input = parse_proving_input(json_str);
        assert!(parsed_input.is_ok());
        let parsed_input = parsed_input.unwrap();
        let v1 = parsed_input["key1"]
            .iter()
            .map(|n| n.to_str_radix(10))
            .join(",");

        let v2 = parsed_input["key2"]
            .iter()
            .map(|n| n.to_str_radix(10))
            .join(",");

        assert_eq!("123,456", v1);
        assert_eq!(
            "5841544268561861499519250994748571,282086110796185156675799806248152448",
            v2
        );
    }
}
