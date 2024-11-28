# Version 2.0.1

## 目录文件功能:

- .env
  - 一些为了安全性而选择不加入代码的敏感数据, 包含 `DATABASE_URL` 和 `ENCODING_KEY`.

- DBbackend.postman_collection.json
  - 后端全部接口测试文件. 可直接导入 postman.

- Initialize.sql
  -  PostgreSQL 数据库初始化代码.

- /src
  - rust 源文件目录.

## 接口
```
POST     /user/login             User login
POST     /user/register          User Register (Admin)
GET      /user/info              Fetch user info
GET      /user/image             Fetch user image
PUT      /user/image             Modify user image
PUT      /user/password          Modify user password
PUT      /user/email             Modify user email
PUT      /user/username          Modify user username
DELETE   /user/cancel            Cancel user account
DELETE   /user/delete/{id}       Delete user account (Admin)
GET      /user/all               Fetch user list (Admin)
POST     /user/upgrade/{id}      Upgrade user (Admin)
POST     /user/dngrade/{id}      Dngrade user (Admin)
POST     /docs                   Upload a document
GET      /docs/all               Fetch all documents
GET      /docs/buffer            Fetch documents in buffer (Admin)
GET      /docs/buffer/{id}       Download a document in buffer for exam (Admin)
PUT      /docs/buffer/{id}       Edit a document in buffer (Admin)
POST     /docs/buffer/{id}       Confirm a document upload is valid (Admin)
DELETE   /docs/buffer/{id}       Refuse a document upload is valid (Admin)
GET      /docs/search/{title}    Search documents by title
GET      /docs/{id}              Download a document
PUT      /docs/{id}              Edit documents information (Admin)
DELETE   /docs/{id}              Delete a document (Admin)
POST     /book                   Add a book (Admin)
GET      /book/all               Fetch all books (Admin)
GET      /book/search/{title}    Search books by title
PUT      /book/{id}              Edit books information (Admin)
DELETE   /book/{id}              Delete a book (Admin)
POST     /book/borrow/{id}       Borrow a book
POST     /book/return/{id}       Return a book
GET      /book/borrowings/all    Fetch all borrowing records (Admin)
GET      /book/{id}              Fetch book information by ID
GET      /book/borrowings        Fetch user borrowing records
GET      /stat                   Fetch statistics (Admin)
GET      /logs                   Fetch logs (Admin)
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