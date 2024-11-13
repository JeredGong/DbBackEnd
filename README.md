## 目录文件功能:

- .env
  一些为了安全性而选择不加入代码的敏感数据, 包含 `DATABASE_URL` 和 `ENCODING_KEY`.

- Initialize.sql
  PostgreSQL 数据库初始化代码.

- test.html
  部分用于测试的前端代码.

- /src
  rust 源文件目录.

-----------------------

# 后端 REST API 文档

## 模块：`user.rs`

### 数据库模式
该模块使用以下表：

- **user**:
  - `id`: bigint (主键, 自动递增)
  - `username`: varchar(256)
  - `password_hash`: varchar(512)
  - `role`: smallint (0 表示管理员, 1 表示普通用户)
  - `image`: bytea

### 枚举
- `Role`: 定义用户角色，可能的值有：
  - `Admin` (管理员)
  - `User` (普通用户)

### 结构体
- `Claims`: 表示从 JWT 提取的声明，包含：
  - `id`: i64
  - `role`: i16
  - `exp`: u64 (过期时间戳)

- `UsersRequest`: 表示创建用户的请求，包含：
  - `username`: String
  - `password_hash`: String
  - `role`: i16

- `UsersResponse`: 表示用户数据的响应结构，包含：
  - `id`: i64
  - `username`: String
  - `role`: i16

### 函数

#### `UnwrapToken`
- 从 `Authorization` 头部提取并解码 JWT token，若有效则返回 `Claims`。

#### `CheckIs`
- 根据提供的声明检查用户是否拥有指定角色。

#### `CheckAdmin`
- 检查经过身份验证的用户是否具有“管理员”角色，并返回有效的声明。

#### `CheckUser`
- 检查经过身份验证的用户是否拥有有效的 token，并返回“普通用户”角色的声明。

### API 接口

#### `POST /login`
- 通过验证用户名和密码登录用户。
- 成功登录后返回 JWT token。
- **请求体**: `{ "username": "string", "password_hash": "string", "role": integer }`
- **响应**: JWT token。

#### `POST /register`
- 注册新用户。普通用户不能注册为管理员。
- **请求体**: `{ "username": "string", "password_hash": "string", "role": integer }`
- **响应**: "Register success."。

#### `DELETE /cancel`
- 允许已认证的用户取消其账户。
- **响应**: "Account Cancellation success."。

#### `DELETE /delete/{id}`
- 允许管理员通过将用户的详细信息设置为 `NULL` 来删除用户。
- **响应**: "Delete account success."。

#### `GET /users`
- 获取所有用户列表（仅管理员可用）。
- **响应**: 用户列表，包括 `id`、`username` 和 `role`。

---

## 模块：`docs.rs`

### 数据库模式
该模块使用以下表：

- **docs**:
  - `id`: bigint (主键)
  - `title`: varchar(256)
  - `pdf_content`: bytea
  - `uploaded_by`: bigint
  - `download_count`: integer
  - `upload_date`: timestamp with time zone

### 结构体
- `DocumentRequest`: 表示添加文档的请求，包含：
  - `title`: String
  - `pdf_content`: Vec<u8>

- `DocumentResponse`: 表示文档响应，包含：
  - `id`: i64
  - `title`: String
  - `upload_date`: OffsetDateTime
  - `download_count`: i32

### 函数

#### `Add`
- 向系统中添加新文档，仅管理员可以添加文档。
- **请求体**: `{ "title": "string", "pdf_content": "byte array" }`
- **响应**: "Document added successfully."。

#### `List`
- 列出系统中的所有文档。
- **响应**: 文档列表，包含 `id`、`title`、`upload_date` 和 `download_count`。

#### `Download`
- 允许用户下载文档，成功下载后增加 `download_count`。
- **响应**: 文档的二进制 PDF 内容。

### API 接口

#### `POST /documents`
- 添加新文档（仅管理员可用）。
- **请求体**: `{ "title": "string", "pdf_content": "byte array" }`
- **响应**: "Document added successfully."。

#### `GET /documents`
- 获取所有文档的列表。
- **响应**: 文档列表，包括 `id`、`title`、`upload_date` 和 `download_count`。

#### `GET /documents/download/{id}`
- 下载指定 `id` 的文档，并增加下载次数。
- **响应**: 文档的二进制 PDF 内容。

## 模块：`book.rs`

### 数据库模式
该模块使用以下表：

- **book**:
  - `id`: bigint (主键)
  - `title`: varchar(256)
  - `author`: varchar(256)
  - `available`: bool

- **recs**:
  - `id`: bigint (主键)
  - `user_id`: bigint
  - `book_id`: bigint
  - `borrowed_at`: timestamp with time zone
  - `returned_at`: timestamp with time zone

### 结构体
- `BookRequest`: 表示创建或更新书籍的请求，包含：
  - `title`: String
  - `author`: String

- `BookResponse`: 表示书籍的响应，包含：
  - `id`: i64
  - `title`: String
  - `author`: String
  - `available`: bool

- `RecordResponse`: 表示借书记录的响应，包含：
  - `id`: i64
  - `userID`: i64
  - `bookID`: i64
  - `borrowedAt`: OffsetDateTime
  - `returnedAt`: OffsetDateTime

### API 接口

#### `POST /books` - 添加新书
- 向 `book` 表中添加新书。
- 需要管理员授权。

#### `GET /books` - 列出所有书籍
- 获取所有书籍的列表，包括可用性。
- 记录管理员请求。

#### `PUT /books/{id}` - 编辑书籍信息
- 更新指定书籍的标题和作者信息。
- 需要管理员授权。

#### `DELETE /books/{id}` - 删除书籍
- 通过将 `available` 设置为 `NULL` 来标记书籍为不可用。
- 需要管理员授权。

#### `POST /borrow/{id}` - 借阅书籍
- 如果书籍可用，标记书籍为已借，并在 `recs` 表中记录借阅事件。

#### `POST /return/{id}` - 归还书籍
- 标记书籍为已归还，并更新借阅记录。
- 恢复书籍在 `book` 表中的可用性。

#### `GET /borrowings/all` - 查看所有借阅记录
- 获取所有借阅记录。
- 需要管理员授权。

#### `GET /borrowings` - 查看用户借阅记录
- 获取已认证用户的借阅记录。

---

## 模块：`stat.rs`

### 结构体
- `StatisticsResponse`: 包含图书和文档的统计数据，包含：
  - `countBook`: i64 (借阅的图书总数)
  - `countDocs`: i64 (下载的文档总数)

### API 接口

#### `GET /statistics` - 获取统计数据
- 获取有关借阅的图书总数和下载的文档总数的统计数据。
- 需要管理员授权。

---

## 模块：`logs.rs`

### 数据库模式
该模块使用以下表：

- **logs**:
  - `id`: bigint (主键)
  - `user_id`: bigint
  - `action`: varchar(512)

### 结构体
- `LogResponse`: 表示日志条目，包含：
  - `id`: i64
  - `userID`: i64
  - `action`: String

### 函数

#### `RecordLog`
- 为指定的操作插入日志条目到 `logs` 表中。

### API 接口

#### `GET /logs` - 查看日志
- 获取 `logs` 表中的所有日志。
- 需要管理员授权。

-----------------------------------------

# Backend REST API Documentation

## Module: `user.rs`

### Database Schema
The following table is used in this module:

- **user**:
  - `id`: bigint (Primary Key, Auto Increment)
  - `username`: varchar(256)
  - `password_hash`: varchar(512)
  - `role`: smallint (0 for Admin, 1 for User)
  - `image`: bytea

### Enums
- `Role`: Defines user roles with possible values:
  - `Admin`
  - `User`

### Structs
- `Claims`: Represents the claims extracted from the JWT, containing:
  - `id`: i64
  - `role`: i16
  - `exp`: u64 (Expiration timestamp)

- `UsersRequest`: Represents a request to create a user, containing:
  - `username`: String
  - `password_hash`: String
  - `role`: i16

- `UsersResponse`: Represents the response structure for user data, containing:
  - `id`: i64
  - `username`: String
  - `role`: i16

### Functions

#### `UnwrapToken`
- Extracts and decodes the JWT token from the `Authorization` header, returning the `Claims` if valid.

#### `CheckIs`
- Checks if the user has the specified role based on the provided claims.

#### `CheckAdmin`
- Checks if the authenticated user has an "Admin" role and returns the claims if valid.

#### `CheckUser`
- Checks if the authenticated user has a valid token and returns the claims for "User" role.

### API Endpoints

#### `POST /login`
- Logs a user in by validating the username and password.
- Returns a JWT token upon successful login.
- **Request Body**: `{ "username": "string", "password_hash": "string", "role": integer }`
- **Response**: JWT token.

#### `POST /register`
- Registers a new user. Non-admin users cannot register as admins.
- **Request Body**: `{ "username": "string", "password_hash": "string", "role": integer }`
- **Response**: "Register success."

#### `DELETE /cancel`
- Allows the authenticated user to cancel their account.
- **Response**: "Account Cancellation success."

#### `DELETE /delete/{id}`
- Allows an admin to delete a user by setting their details to `NULL`.
- **Response**: "Delete account success."

#### `GET /users`
- Retrieves a list of all users (Admin only).
- **Response**: List of users with their `id`, `username`, and `role`.

---

## Module: `docs.rs`

### Database Schema
The following table is used in this module:

- **docs**:
  - `id`: bigint (Primary Key)
  - `title`: varchar(256)
  - `pdf_content`: bytea
  - `uploaded_by`: bigint
  - `download_count`: integer
  - `upload_date`: timestamp with time zone

### Structs
- `DocumentRequest`: Represents a request to add a document, containing:
  - `title`: String
  - `pdf_content`: Vec<u8>

- `DocumentResponse`: Represents the response for documents, containing:
  - `id`: i64
  - `title`: String
  - `upload_date`: OffsetDateTime
  - `download_count`: i32

### Functions

#### `Add`
- Adds a new document to the system. Only admins can add documents.
- **Request Body**: `{ "title": "string", "pdf_content": "byte array" }`
- **Response**: "Document added successfully."

#### `List`
- Lists all documents in the system.
- **Response**: List of documents with `id`, `title`, `upload_date`, and `download_count`.

#### `Download`
- Allows a user to download a document. Increases the `download_count` upon successful download.
- **Response**: Binary PDF content of the document.

### API Endpoints

#### `POST /documents`
- Adds a new document (Admin only).
- **Request Body**: `{ "title": "string", "pdf_content": "byte array" }`
- **Response**: "Document added successfully."

#### `GET /documents`
- Retrieves a list of all documents.
- **Response**: List of documents with `id`, `title`, `upload_date`, and `download_count`.

#### `GET /documents/download/{id}`
- Downloads a document by `id`, increments the download count.
- **Response**: Binary PDF content.

## Module: `book.rs`

### Database Schema
The following tables are used in this module:

- **book**:
  - `id`: bigint (Primary Key)
  - `title`: varchar(256)
  - `author`: varchar(256)
  - `available`: bool

- **recs**:
  - `id`: bigint (Primary Key)
  - `user_id`: bigint
  - `book_id`: bigint
  - `borrowed_at`: timestamp with time zone
  - `returned_at`: timestamp with time zone

### Structs
- `BookRequest`: Represents a request for creating or updating a book, containing:
  - `title`: String
  - `author`: String

- `BookResponse`: Response struct for books, containing:
  - `id`: i64
  - `title`: String
  - `author`: String
  - `available`: bool

- `RecordResponse`: Response struct for book borrowing records, containing:
  - `id`: i64
  - `userID`: i64
  - `bookID`: i64
  - `borrowedAt`: OffsetDateTime
  - `returnedAt`: OffsetDateTime

### API Endpoints

#### `POST /books` - Add a New Book
- Adds a new book to the `book` table.
- Requires admin authorization.

#### `GET /books` - List All Books
- Retrieves a list of all books, including availability.
- Logs the admin request.

#### `PUT /books/{id}` - Edit Book Details
- Updates the title and author of a specific book by `id`.
- Requires admin authorization.

#### `DELETE /books/{id}` - Delete a Book
- Marks a book as unavailable by setting `available` to `NULL`.
- Requires admin authorization.

#### `POST /borrow/{id}` - Borrow a Book
- Marks a book as borrowed by a user if available.
- Records the borrowing event in the `recs` table.

#### `POST /return/{id}` - Return a Book
- Marks a book as returned and updates the borrowing record.
- Restores the book's availability in the `book` table.

#### `GET /borrowings/all` - View All Borrowing Records
- Retrieves all borrowing records.
- Requires admin authorization.

#### `GET /borrowings` - View User Borrowing Records
- Retrieves borrowing records for the authenticated user.

---

## Module: `stat.rs`

### Structs
- `StatisticsResponse`: Contains statistical data for books and documents, including:
  - `countBook`: i64 (Total borrowed books)
  - `countDocs`: i64 (Total document downloads)

### API Endpoints

#### `GET /statistics` - Get Statistics
- Retrieves statistics on total books borrowed and documents downloaded.
- Requires admin authorization.

---

## Module: `logs.rs`

### Database Schema
The following table is used in this module:

- **logs**:
  - `id`: bigint (Primary Key)
  - `user_id`: bigint
  - `action`: varchar(512)

### Structs
- `LogResponse`: Represents a log entry, containing:
  - `id`: i64
  - `userID`: i64
  - `action`: String

### Functions

#### `RecordLog`
- Inserts a log entry into the `logs` table for a specified action.

### API Endpoints

#### `GET /logs` - View Logs
- Retrieves all logs from the `logs` table.
- Requires admin authorization.

