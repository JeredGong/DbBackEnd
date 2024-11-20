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
GET      /book/borrowings        Fetch user borrowing records
GET      /stat                   Fetch statistics (Admin)
GET      /logs                   Fetch logs (Admin)
```