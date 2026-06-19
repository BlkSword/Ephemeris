//! Python bindings for Ephemeris — message-level deniable encryption.
//!
//! All cryptographic operations are performed in Rust. The Python layer
//! is a thin wrapper converting between Python types and Rust types.
//!
//! All Python-facing functions return `PyResult` so that Rust panics
//! are caught by PyO3's panic hook instead of aborting the process.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ephemeris_core::{
    build_eph as _core_build_eph, build_key as _core_build_key, decrypt as _core_decrypt,
    encrypt as _core_encrypt, generate_salt as _core_generate_salt, parse_eph as _core_parse_eph,
    parse_key as _core_parse_key, repudiate as _core_repudiate,
    repudiate_eph as _core_repudiate_eph, unwrap_key as _core_unwrap_key,
    wrap_key as _core_wrap_key, Argon2Params,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_salt(salt: &[u8]) -> PyResult<[u8; 16]> {
    salt.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("salt must be exactly 16 bytes"))
}

fn resolve_params(p: Option<&PyArgon2Params>) -> Argon2Params {
    p.map(|x| x.inner.clone()).unwrap_or_default()
}

fn format_err(e: impl std::fmt::Display) -> pyo3::PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// Argon2Params
// ---------------------------------------------------------------------------

#[pyclass(name = "Argon2Params")]
#[derive(Clone)]
pub struct PyArgon2Params {
    inner: Argon2Params,
}

#[pymethods]
impl PyArgon2Params {
    #[new]
    #[pyo3(signature = (time_cost = 2, memory_cost = 37888, parallelism = 1))]
    fn new(time_cost: u32, memory_cost: u32, parallelism: u32) -> Self {
        PyArgon2Params {
            inner: Argon2Params {
                time_cost,
                memory_cost,
                parallelism,
            },
        }
    }

    #[staticmethod]
    fn low_memory() -> Self {
        PyArgon2Params {
            inner: Argon2Params::low_memory(),
        }
    }

    #[staticmethod]
    fn moderate() -> Self {
        PyArgon2Params {
            inner: Argon2Params::moderate(),
        }
    }

    #[staticmethod]
    fn default_params() -> Self {
        PyArgon2Params {
            inner: Argon2Params::default(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Argon2Params(time_cost={}, memory_cost={}, parallelism={})",
            self.inner.time_cost, self.inner.memory_cost, self.inner.parallelism
        )
    }
}

// ---------------------------------------------------------------------------
// pyfunctions — Key wrapping (low-level, public)
// ---------------------------------------------------------------------------

/// Generate a random 16-byte salt.
#[pyfunction]
fn generate_salt(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let salt = _core_generate_salt();
    Ok(PyBytes::new(py, &salt).unbind())
}

/// Wrap (encrypt) an OTP key with a password. Returns key_blob.
#[pyfunction]
fn wrap_key(
    py: Python<'_>,
    key: Vec<u8>,
    password: Vec<u8>,
    salt: Vec<u8>,
    params: &PyArgon2Params,
) -> PyResult<Py<PyBytes>> {
    let s = make_salt(&salt)?;
    let blob = _core_wrap_key(&key, &password, &s, &params.inner)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &blob).unbind())
}

/// Unwrap (decrypt) an OTP key. Always succeeds — wrong password → garbage.
#[pyfunction]
fn unwrap_key(
    py: Python<'_>,
    blob: Vec<u8>,
    password: Vec<u8>,
    salt: Vec<u8>,
    params: &PyArgon2Params,
) -> PyResult<Py<PyBytes>> {
    let s = make_salt(&salt)?;
    let key = _core_unwrap_key(&blob, &password, &s, &params.inner)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &key).unbind())
}

// ---------------------------------------------------------------------------
// pyfunctions — Repudiation
// ---------------------------------------------------------------------------

/// Generate a fake key blob decrypting ciphertext to fake_plaintext.
#[pyfunction]
fn repudiate(
    py: Python<'_>,
    ciphertext: Vec<u8>,
    fake_plaintext: Vec<u8>,
    fake_password: Vec<u8>,
    salt: Vec<u8>,
    params: &PyArgon2Params,
) -> PyResult<Py<PyBytes>> {
    if ciphertext.len() != fake_plaintext.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "length mismatch: ct={}, fake_pt={}",
            ciphertext.len(),
            fake_plaintext.len()
        )));
    }
    let s = make_salt(&salt)?;
    let blob = _core_repudiate(
        &ciphertext,
        &fake_plaintext,
        &fake_password,
        &s,
        &params.inner,
    )
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &blob).unbind())
}

// ---------------------------------------------------------------------------
// pyfunctions — File format
// ---------------------------------------------------------------------------

/// Parse a .eph file. Returns (salt, key_blob, ciphertext).
#[pyfunction]
fn parse_eph(py: Python<'_>, data: Vec<u8>) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    let parsed = _core_parse_eph(&data).map_err(format_err)?;
    Ok((
        PyBytes::new(py, &parsed.salt).unbind(),
        PyBytes::new(py, parsed.key_blob).unbind(),
        PyBytes::new(py, parsed.ciphertext).unbind(),
    ))
}

/// Build a .eph file from components.
#[pyfunction]
fn build_eph(
    py: Python<'_>,
    salt: Vec<u8>,
    key_blob: Vec<u8>,
    ciphertext: Vec<u8>,
) -> PyResult<Py<PyBytes>> {
    let s = make_salt(&salt)?;
    let data = _core_build_eph(&s, &key_blob, &ciphertext);
    Ok(PyBytes::new(py, &data).unbind())
}

/// Parse a .key file. Returns (salt, key_blob).
#[pyfunction]
fn parse_key(py: Python<'_>, data: Vec<u8>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (salt, blob) = _core_parse_key(&data).map_err(format_err)?;
    Ok((
        PyBytes::new(py, &salt).unbind(),
        PyBytes::new(py, blob).unbind(),
    ))
}

/// Build a .key file from components.
#[pyfunction]
fn build_key(py: Python<'_>, salt: Vec<u8>, key_blob: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let s = make_salt(&salt)?;
    let data = _core_build_key(&s, &key_blob);
    Ok(PyBytes::new(py, &data).unbind())
}

// ---------------------------------------------------------------------------
// pyfunctions — High-level
// ---------------------------------------------------------------------------

/// Encrypt plaintext with a password. Returns .eph file bytes.
#[pyfunction]
#[pyo3(signature = (plaintext, password, params = None))]
fn encrypt(
    py: Python<'_>,
    plaintext: Vec<u8>,
    password: Vec<u8>,
    params: Option<&PyArgon2Params>,
) -> PyResult<Py<PyBytes>> {
    let p = resolve_params(params);
    let result = _core_encrypt(&plaintext, &password, &p);
    Ok(PyBytes::new(py, &result.eph_file).unbind())
}

/// Decrypt a .eph file. Always returns bytes — wrong password → garbage.
/// Raises ValueError only if the file format is invalid.
#[pyfunction]
#[pyo3(signature = (eph_data, password, params = None))]
fn decrypt(
    py: Python<'_>,
    eph_data: Vec<u8>,
    password: Vec<u8>,
    params: Option<&PyArgon2Params>,
) -> PyResult<Py<PyBytes>> {
    let p = resolve_params(params);
    let pt = _core_decrypt(&eph_data, &password, &p).map_err(format_err)?;
    Ok(PyBytes::new(py, &pt).unbind())
}

/// Repudiate: replace key so it decrypts to fake_plaintext with fake_password.
/// Returns new .eph file bytes.
/// Raises ValueError if format is invalid or lengths mismatch.
#[pyfunction]
#[pyo3(signature = (eph_data, fake_plaintext, fake_password, params = None))]
fn repudiate_eph(
    py: Python<'_>,
    eph_data: Vec<u8>,
    fake_plaintext: Vec<u8>,
    fake_password: Vec<u8>,
    params: Option<&PyArgon2Params>,
) -> PyResult<Py<PyBytes>> {
    let p = resolve_params(params);
    let new_eph =
        _core_repudiate_eph(&eph_data, &fake_plaintext, &fake_password, &p).map_err(format_err)?;
    Ok(PyBytes::new(py, &new_eph).unbind())
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

#[pymodule]
fn ephemeris(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyArgon2Params>()?;
    m.add_function(wrap_pyfunction!(generate_salt, m)?)?;
    m.add_function(wrap_pyfunction!(wrap_key, m)?)?;
    m.add_function(wrap_pyfunction!(unwrap_key, m)?)?;
    m.add_function(wrap_pyfunction!(repudiate, m)?)?;
    m.add_function(wrap_pyfunction!(parse_eph, m)?)?;
    m.add_function(wrap_pyfunction!(build_eph, m)?)?;
    m.add_function(wrap_pyfunction!(parse_key, m)?)?;
    m.add_function(wrap_pyfunction!(build_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(repudiate_eph, m)?)?;
    Ok(())
}
