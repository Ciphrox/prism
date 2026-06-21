use anyhow::Result;

use rcgen::{CertificateParams, KeyPair};
use std::{fs, path::Path};

pub fn generate_identity(common_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;

    let params = CertificateParams::new(vec![common_name.to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().as_ref().to_vec();
    let key_der = key_pair.serialized_der().to_vec();

    Ok((cert_der, key_der))
}

pub fn save_trusted_cert(dir: &Path, common_name: &str, cert_der: &Vec<u8>) -> Result<()> {
    fs::create_dir_all(dir)?;

    let cert_path = dir.join(format!("{}.der", common_name));
    fs::write(cert_path, cert_der)?;

    Ok(())
}

pub fn load_trusted_certs(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    if !dir.exists() {
        return Ok(certs);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|ext| ext.to_str()) == Some("der") {
            certs.push(fs::read(path)?);
        }
    }

    Ok(certs)
}

pub fn remove_trusted_cert(dir: &Path, common_name: &str) -> Result<()> {
    let cert_path = dir.join(format!("{}.der", common_name));
    fs::remove_file(cert_path)?;

    Ok(())
}

pub fn load_or_generate_identity(
    config_dir: &Path,
    common_name: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    //load
    let identity_dir = config_dir.join("identity");
    let cert_path = identity_dir.join("cert.der");
    let key_path = identity_dir.join("key.der");

    if cert_path.exists() && key_path.exists() {
        let cert_der = fs::read(&cert_path)?;
        let key_der = fs::read(&key_path)?;

        return Ok((cert_der, key_der));
    }

    //generate
    let (cert_der, key_der) = generate_identity(common_name)?;

    fs::create_dir_all(&identity_dir)?;
    fs::write(&cert_path, &cert_der)?;
    fs::write(&key_path, &key_der)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms)?;
    }

    Ok((cert_der, key_der))
}
