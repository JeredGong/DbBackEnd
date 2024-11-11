# DbBackEnd
这里是DB大作业的后端

### 0.0.1
- 接口：
    - Users Login: /POST 用户登录
    - Users Register: /POST 用户注册 (管理员用户仅管理员可注册)
    - User Delete: /DELETE 用户注销

- 函数：
    - UnwrapToken: 解包 Token, 得到 Claims
    - CheckIs: 根据 Claims 判断用户是否为 Admin 或 User