![icon](ico/icon.ico)

# SSLCertificateSplittingTool

[ English | [中文](#ssl-证书文件拆分工具)]

This tool is used to split a certificate file containing multiple certificates into multiple separate certificate files, and name the files according to the certificate chain order and the subject name. It also supports being used as a certificate information viewer.

SSL certificate files usually contain multiple certificates, such as root certificates, intermediate certificates, client certificates, etc. Certificate files with multiple certificates are usually larger, and on some embedded devices with limited storage space, this may prevent the certificate file containing multiple certificates from being used directly, so it needs to be split into multiple separate certificate files.

## Configuration Requirements

- Software Version: 1.0.0
- GO Version: [1.22.2](https://tip.golang.org/doc/go1.22)
- Operating System:
  - Windows 10 or above
  - MacOS 10.15 or above
  - Linux Ubuntu 16.04 LTS or above

## Usage

`./SSLCertificateSplit -i <input_file> -o <output_dir> -v -pa`

- `-i <file_path>`: The X509 certificate file path to load.
- `-o <directory_path>`: Output directory without the last `/`. If empty, the file will not be saved. The default path is `./out`.
- `-v`: Display detailed information about the certificate.
- `-pa`: Pause before writing the file and after execution. If the first parameter is the X509 certificate file path (open with mode), this item is forced to be turned on.

Command example: `./SSLCertificateSplit -i client.pem -o "./out" -v`.

### Certificate information viewing mode

If you don't want to actually split the file, just want to view the certificate information, you can set the `-o` parameter to `""` and use the `-v` parameter, so that only the detailed information of the certificate will be displayed, and no file will be generated.

Command example: `./SSLCertificateSplit -i client.pem -o "" -v`.

### Windows operating system

On the Windows operating system, you can directly open the certificate file with the exe, display the certificate chain information, and after confirmation, generate an `out` folder in the current directory, which contains the split certificate file.

### Non-Windows operating systems

On non-Windows operating systems, you can run this tool through the command line. Before using it, please execute `chmod +x ./SSLCertificateSplit` to grant execution permissions.

## License

Copyright (c) 2024 KagurazakaYashi@Tongdy SSLCertificateSplittingTool is licensed under Mulan PSL v2. You can use this software according to the terms and conditions of the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at: http://license.coscl.org.cn/MulanPSL2 THIS SOFTWARE IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the Mulan PSL v2 for more details.

## SSL 证书文件拆分工具

本工具用于将一个包含多个证书的证书文件拆分为多个单独的证书文件，并根据证书链顺序和使用者名称为文件命名。也支持作为证书信息查看器。

SSL 证书文件通常具有多个证书，例如：根证书、中间证书、客户端证书等。具有多个证书的证书文件通常较大，而在某些存储空间局限的嵌入式设备上，这可能导致无法直接使用包含多个证书的证书文件，因此需要将其拆分为多个单独的证书文件。

## 配置要求

- 软件版本：1.0.0
- GO 版本：[1.22.2](https://tip.golang.org/doc/go1.22)
- 操作系统：
  - Windows 10 或以上版本
  - MacOS 10.15 或以上版本
  - Linux Ubuntu 16.04 LTS 或以上版本

## 使用方法

`./SSLCertificateSplit -i <input_file> -o <output_dir> -v -pa`

- `-i <文件路径>`: 要加载的 X509 证书文件路径。
- `-o <目录路径>`: 输出目录，不带最后的 `/` 。为空则不保存文件。默认路径为 `./out` 。
- `-v`: 显示证书的详细信息。
- `-pa`: 写入文件前和执行完毕后暂停。如果第一个参数为 X509 证书文件路径（打开方式）则此项强制开启。

命令示例: `./SSLCertificateSplit -i client.pem -o "./out" -v` 。

### 证书信息查看模式

如果不想实际拆分文件，只是想查看证书信息，可以将 `-o` 参数设置为 `""` 并使用 `-v` 参数，这样将只显示证书的详细信息，不会生成文件。

命令示例: `./SSLCertificateSplit -i client.pem -o "" -v` 。

### Windows 系统

在 Windows 操作系统上，可以将证书文件直接用该 exe 打开，将显示证书链信息，并在确认后在当前目录下生成一个 `out` 文件夹，里面包含了拆分后的证书文件。

### 非 Windows 系统

在非 Windows 操作系统上，可以通过命令行运行该工具，在使用之前，请先执行 `chmod +x ./SSLCertificateSplit` 赋予执行权限。

## 许可证

Copyright (c) 2024 KagurazakaYashi@Tongdy SSLCertificateSplittingTool is licensed under Mulan PSL v2. You can use this software according to the terms and conditions of the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at: http://license.coscl.org.cn/MulanPSL2 THIS SOFTWARE IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the Mulan PSL v2 for more details.
