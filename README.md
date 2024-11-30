# Version 2.0.1

## 目录文件功能:

- .env
  - 一些为了安全性而选择不加入代码的敏感数据, 包含 `DATABASE_URL` 和 `ENCODING_KEY`.
  - 后端的连接端口为`BACKEND_ADDR`,默认值是本地端口9876

- DBbackend.postman_collection.json
  - 后端全部接口测试文件. 可直接导入 postman.

- Initialize.sql
  -  PostgreSQL 数据库初始化代码.

- /src
  - rust 源文件目录.

## 接口
```
.service(user::Login)           // POST     /user/login             User login
.service(user::Register)        // POST     /user/register          User Register (Admin)
.service(user::GetInfo)         // GET      /user/info              Fetch user info
.service(user::GetUserImage)    // GET      /user/image             Fetch user self image
.service(user::GetImage)        // GET      /user/image             Fetch image of user by ID
.service(user::ModifyImage)     // PUT      /user/image             Modify user image
.service(user::ModifyPasswd)    // PUT      /user/password          Modify user password
.service(user::ModifyEmail)     // PUT      /user/email             Modify user email
.service(user::ModifyUsername)  // PUT      /user/username          Modify user username
.service(user::Cancel)          // DELETE   /user/cancel            Cancel user account
.service(user::Delete)          // DELETE   /user/delete/{id}       Delete user account (Admin)
.service(user::Users)           // GET      /user/all               Fetch user list (Admin)
.service(user::Upgrade)         // POST     /user/upgrade/{id}      Upgrade user (Admin)
.service(user::Dngrade)         // POST     /user/dngrade/{id}      Dngrade user (Admin)
.service(docs::Add)             // POST     /docs                   Upload a document
.service(docs::List)            // GET      /docs/all               Fetch all documents
.service(docs::GetBuffer)       // GET      /docs/buffer            Fetch documents in buffer (Admin)
.service(docs::DownloadBuffer)  // GET      /docs/buffer/{id}       Download a document in buffer for exam (Admin)
.service(docs::EditBuffer)      // PUT      /docs/buffer/{id}       Edit a document in buffer (Admin)
.service(docs::ConfirmBuffer)   // POST     /docs/buffer/{id}       Confirm a document upload is valid (Admin)
.service(docs::RefuseBuffer)    // DELETE   /docs/buffer/{id}       Refuse a document upload is valid (Admin)
.service(docs::Search)          // GET      /docs/search/{title}    Search documents by title
.service(docs::Download)        // GET      /docs/{id}              Download a document
.service(docs::Edit)            // PUT      /docs/{id}              Edit documents information (Admin)
.service(docs::Delete)          // DELETE   /docs/{id}              Delete a document (Admin)
.service(book::Add)             // POST     /book                   Add a book (Admin)
.service(book::List)            // GET      /book/all               Fetch all books (Admin)
.service(book::Search)          // GET      /book/search/{title}    Search books by title
.service(book::Edit)            // PUT      /book/{id}              Edit books information (Admin)
.service(book::Delete)          // DELETE   /book/{id}              Delete a book (Admin)
.service(book::Borrow)          // POST     /book/borrow/{id}       Borrow a book
.service(book::Return)          // POST     /book/return/{id}       Return a book
.service(book::Records)         // GET      /book/borrowings/all    Fetch all borrowing records (Admin)
.service(book::GetBookById)     // GET      /book/{id}              Fetch book information by ID
.service(book::UserRecords)     // GET      /book/borrowings        Fetch user borrowing records
.service(stat::Statistics)      // GET      /stat                   Fetch statistics (Admin)
.service(logs::Logs)            // GET      /logs                   Fetch logs (Admin)
```
## 错误说明
### user
```
pub async fn UnwrapToken()
  - 404   User not found
  - 401   User role unmatched with database. Please re-login.
  - 400   Decode failed.
  - 400   Failed to fetch and parse token.
pub fn CheckIs()
  - 401   Role invalid.
pub async fn CheckAdmin()
  - 401   Only admins can perform this action.
pub async fn CheckUser()
  - 401   Only users can perform this action.
pub async fn Login()
  - 404   User not found.
  - 401   Invalid password.
  - 404   Password not found.
  - 500   Failed to create Token.
pub async fn Register()
  - 500   Failed to start transaction.
  - 500   Failed to create upload directory
  - 500   Failed to save image
  - 500   Insert failed.\nDatabase error:
  - 500   Fetch user ID failed.
  - 500   Failed to commit transaction.
pub async fn GetInfo()
  - 500   Insert failed.
pub async fn GetImage()
  - 500   Fetch image failed.
pub async fn ModifyImage()
  - 500   Failed to create upload directory
  - 500   Failed to save image
  - 500   Failed to update user image.
pub async fn ModifyPasswd()
  - 500   Failed to update user password.
pub async fn ModifyEmail()
  - 500   Failed to update user email.
pub async fn ModifyUsername()
  - 500   Failed to update user username.
pub async fn Cancel()
  - 500   Insert failed.
pub async fn Delete()
  - 500   Insert failed.
pub async fn Users()
  - 500   Search failed.
pub async fn Upgrade()
  - 500   Upgrade user failed.
pub async fn Dngrade()
  - 403   Administrators cannot self-dngrade.
  - 500   Degrade user failed.
pub async fn GetImageFile()
  - 400   Invalid image path
  - 404   Image not found
  - 500   Failed to read image file
```
### stat
```
pub async fn Statistics()
  - 500   Failed to start transaction.
  - 500   Failed to get books borrowed count.
  - 500   Failed to get documents downloaded count.
  - 500   Failed to commit transaction.
```
### logs
```
pub async fn RecordLog()
  - 500   Failed to insert log.
pub async fn Logs()
  - 500   Failed to fetch logs.
```
### docs
```
pub async fn Add()
  - 500   Failed to save PDF file
  - 500   Failed to insert into docs table
  - 500   Failed to insert into buff table
  - 500   Failed to record log
pub async fn List()
  - 500   Failed to retrieve documents.
pub async fn GetBuffer()
  - 500   Failed to retrieve documents.
pub async fn DownloadBuffer()
  - 404   Document not found
  - 500   Failed to read PDF file
pub async fn EditBuffer()
  - 500   Failed to save PDF file
  - 500   Failed to edit buffer document
pub async fn ConfirmBuffer()
  - 500   Failed to start transaction.
  - 404   Document not found in buffer.
  - 500   Failed to insert document into docs table.
  - 500   Failed to delete document from buffer.
  - 500   Failed to commit transaction.
pub async fn RefuseBuffer()
  - 404   Document not found in buffer.
  - 500   Delete document failed.
  - 500   Failed to delete document file from storage
pub async fn Search()
  - 500   Failed to retrieve documents.
  - 404   Document not found.
pub async fn Download()
  - 404   Document not found.
  - 500   Failed to read PDF file
  - 500   Failed to update download count.
pub async fn Edit()
  - 500   Failed to save PDF file
  - 500   Failed to edit document.
async fn Delete()
  - 500   Failed to delete document.
```
### book
```
pub async fn Add()
  - 500   Failed to start transaction.
  - 500   Failed to add book.
  - 404   Failed to add book.
  - 500   Failed to commit transaction.
pub async fn List()
  - 404   Failed to retrieve books.
pub async fn Search()
  - 500   Failed to retrieve books.
pub async fn Edit()
  - 500   Failed to edit book.
pub async fn Delete()
  - 500   Failed to delete book.
pub async fn Borrow()
  - 500   Failed to start transaction.
  - 403   Failed to borrow book.
  - 500   Failed to borrow book.
  - 500   Failed to insert borrowing record.
  - 500   Failed to commit transaction.
pub async fn Return()
  - 500   Failed to start transaction.
  - 403   Valid borrowing record not found.
  - 500   Failed to update borrowing record
  - 500   Failed to insert borrowing record.
  - 500   Failed to commit transaction.
pub async fn Records()
  - 404   Failed to fetch borrowing records.
pub async fn UserRecords()
  - 404   Failed to fetch borrowing records.
pub async fn GetBookById()
  - 404   Failed to fetch book details by ID.
```