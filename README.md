# DbBackEnd
这里是DB大作业的后端

### 0.0.1
- 接口：
    - Users::Login      /POST       用户登录
    - Users::Register   /POST       用户注册 (仅管理员账户可创建管理员账户)
    - Users::Cancel     /DELETE     用户注销
    - Users::Delete     /DELETE     用户删除 (管理员)
    - Users::Users      /GET        获取用户列表 (管理员)

- 函数：
    - UnwrapToken: 解包 Token, 得到 Claims
    - CheckIs: 根据 Claims 判断用户是否为 Admin 或 User