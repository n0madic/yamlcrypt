# yamlcrypt

Tool is intended for symmetric encryption/decryption of associative array values in the yaml files.

All language versions are compatible with each other.

## Help

```shell
Utility to encrypt/decrypt YAML values (decrypt by default).

Usage: yamlcrypt [options] FILE
  -encrypt
        Encrypt values
  -key string
        The key in YAML for encryption (default "secrets")
  -password string
        Password for encryption. NOT SAFE!
        It is better to use the environment variable $YAML_PASSWORD
```

## Building Go version

```shell
go get -u gopkg.in/yaml.v2
go build yamlcrypt.go
```

## Requirements for PHP version

`yamlcrypt.php` requires yaml extension to be installed.

```shell
pecl install yaml
```

or

```shell
apt-get install php-yaml
```

## Requirements for Python version

`yamlcrypt.py` requires yaml extension to be installed.

```shell
pip install pyyaml
```

or

```shell
apt-get install python-yaml
```

## Requirements for Rust version

`yamlcrypt.rs` requires `Cargo.toml` with dependencies.

```shell
cargo build --release
```
