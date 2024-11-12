# DbBackEnd
这里是DB大作业的后端

### 0.0.1
- 接口：
    - Users::Login      POST/login      用户登录
    - Users::Register   POST/register   用户注册 (仅管理员账户可创建管理员账户)
    - Users::Cancel     DELETE/cancel   用户注销
    - Users::Delete     DELETE/delete   用户删除 (管理员)
    - Users::Users      GET/users       获取用户列表 (管理员)

- 函数：
    - UnwrapToken: 解包 Token, 得到 Claims
    - CheckIs: 根据 Claims 判断用户是否为 Admin 或 User


### 0.0.2
- 接口:
    - Docs::add_document        POST/documents                  增加论文 (管理员)
    - Docs::list_documents      GET/documents                   获取全部论文
    - Docs::download_document   GET/documents/download/{id}     下载论文 
    - Docs::edit_document       PUT/documents/{id}              编辑论文
    - Docs::delete_document     DELETE/documents/{id}           删除论文 (管理员)

- 函数:
    - check_admin: 判断是否为管理员

