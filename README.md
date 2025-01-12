# EncryptWebDAV

EncryptWebDAV是一个用于加密和解密WebDAV请求的Go语言实现。它充当客户端和上游WebDAV服务器之间的代理，确保传输的数据是加密的。

## 功能

- **加密上传**：通过PUT方法上传文件时，数据会被加密。
- **解密下载**：通过GET方法下载文件时，数据会被解密。
- **支持多种WebDAV方法**：包括DELETE、MKCOL、PROPFIND、OPTIONS、MOVE等。
- **自定义上游服务器**：通过Basic认证头部指定上游服务器URL和认证信息。

## 安装

1. 确保已安装Go 1.23或更高版本。
2. 克隆此仓库：
   ```bash
   git clone <repository-url>
   ```
3. 进入项目目录并构建：
   ```bash
   cd encryptWebDAV
   go build
   ```

## 使用

1. 启动服务器：
   ```bash
   ./encryptWebDAV
   ```
   默认情况下，服务器将在`localhost:8080`上运行。可以通过设置`PORT`环境变量来更改端口。

2. 配置客户端以使用EncryptWebDAV作为WebDAV服务器。

## 配置

- **环境变量**：
  - `PORT`：指定服务器监听的端口。

- **认证信息**：
  - 通过Basic认证头部传递上游服务器URL和认证信息。用户名部分为上游URL的Base64编码，密码部分为包含AES密钥和上游认证信息的JSON对象的Base64编码。

## 代码结构

- `main.go`：应用程序的入口点，定义了WebDAV处理逻辑。
- `go.mod`：Go模块文件，定义了模块名称和Go版本。

## 贡献

欢迎提交问题和请求。请确保在提交请求之前先创建一个问题以讨论更改。

## 许可证

此项目使用MIT许可证。有关详细信息，请参阅LICENSE文件。
