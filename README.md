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