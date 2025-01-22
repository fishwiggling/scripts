# Scripts Repository

Common Scripts repository!

#### Features
- easy use

## Script Overview

### ideb.sh

The `ideb.sh` script allows you to reinstall from a Debian system to the latest Debian Stable version.


#### Parameters
- `-p <password>`: Set user password

#### Example Usage
```bash
wget -qO- 'https://raw.githubusercontent.com/fishwiggling/scripts/master/ideb.sh' | sudo bash -s -- \
--confirm -p 'Ideb123'
```

## Contributing
We welcome any form of contributions! Please follow these steps:
1. **Fork** this repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push the changes to your branch (`git push origin feature/YourFeature`).
5. Submit a Pull Request.

Please ensure to follow our coding standards and provide clear descriptions when submitting.

## License

This project is licensed under the [ BSD 3 License](LICENSE). For more details, please refer to the license file.
