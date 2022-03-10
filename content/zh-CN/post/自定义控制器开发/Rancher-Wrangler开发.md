# 开发说明

使用Rancher Wrangler框架可以方便地开发自定义资源(crd)控制器, 与诸如kubebuilder, operator-sdk等一样, 都是一种kubernetes自定义资源和控制器的脚手架, 用于自定义资源通用代码的自动生成. wrangler中还封装了一系列丰富便捷的API供开发者使用. 采用Wrangler框架开发的crd控制器即可以作为独立的Operator, 也可以集成到Rancher源码中作为内置的自定义资源控制器.

## 独立Operator

基于Wrangler的示例仓库`wrangler-sample`

主要包含五部分: 

- 自定义资源yaml清单(包括自定义资源声明和自定义资源实例)
- license声明样版(自动生成的代码会在头部添加这些声明样版内容)
- 自定义资源types.go
- 代码自动生成声明codegen(自动生成的是自定义资源及其控制器的通用接口)
- 自定义控制器逻辑(简单示例仅包含main.go和controller.go两个文件)

整体逻辑是在types.go定义自定义资源的结构和字段, 然后利用wrangler的codegen自动生成(go generate)自定义资源及其控制器的通用接口, 其中资源接口位于`pkg/apis`目录, 控制器接口位于`pkg/generated`目录.  而真正的控制器逻辑在外层的`controller.go`中实现, 其中包括自定义资源注册函数`Register`和事件响应逻辑. 在自定义控制器逻辑中, 可以使用`client-go`和`wrangler`封装好的调用.

> 需要在main.go中加入//go generate字样以便golang调用代码自动生成程序
>
> 自动生成工具会生成很多自定义资源调用接口, 但通常只需要`pkg/api`和`pkg/generated/controller`中的代码, 其他自动生成代码是可以删除的.

在`controller.go`中实现自定义字样控制逻辑后, 在`main.go`中加入kubernetes连接, 控制器注册和运行代码就完成了一个简单的独立Operator的开发. 这些代码同样在wrangler框架中进行了封装. `go build`后生成二进制文件直接运行即可. 二进制文件打包到容器中即可作为operator运行在kubernetes集群中.

自定义控制器起作用需要kubernetes集群中运行了自定义资源和自定义资源示例, 对于独立Operator, 自定义资源及其实例均可通过`apply`的方式手动添加.

## 源码集成

wrangler开发的自定义资源控制器在源码中是通过wrangler控制器进行管理的(`pkg/controllers/management/wrangler.go`), 在wrangler控制器中注册后即可在rancher中生效. 相当于wrangler控制器代替了独立operator的main.go的程序入口功能.

整体逻辑是先在wrangler的上下文(`pkg/wrangler/context.go`)中引入自定义资源控制器的handler(或factory, manager等), 然后在wrangler的注册函数(`pkg/ocntrollers/management/wrangler.go`)中调用自定义控制器`controller.go`的`Register`函数完成自定义资源控制器的注册. 在注册过程中可以选择传入`全局上下文`, `wrangler上下文`, `全局管理上下文`和`集群管理器`, 全局上下文用于响应程序退出, 其他上下文中已经实例化了大量管理器, 资源控制器, 连接客户端等.

自定义资源的相关代码在Rancher源码中有约定俗成的保存位置, 其中`controller.go`(需要修改文件的package名)保存在`pkg/controllers/foo/bar/`目录下(根据功能自行决定foo, bar目录名), `pkg/api`目录下的文件同样保存到rancher源码的`pkg/api`目录下, `pkg/generated`目录下的`controllers`目录(其他目录不需要)还是保存在rancher源码的`pkg/generated`目录下.

对于源码集成的自定义资源控制器, 自定义资源应当在rancher启动的时候自动生成在集群中, 在`pkg/crds/management/crds.go`中调用`newCRD`即可自动完成自定义资源的创建.

监听资源的两个事件: OnChange, OnRemove. 需要注意的是, 当删除被监听资源时, Kubernetes API删除操作会首先将资源的`DeletionTimestamp`字段设置为时间戳, 然后等待资源的**finalizers**(如果有)作最后的处理, 处理完成之后资源才会真正删除, 也就是说, 删除操作也会先触发OnChange事件, 然后资源被删除, 最后才会触发OnRemove事件. 所以如果不希望资源删除过程中触发OnChange事件定义的回调流程, 应当在OnChange回调流程中判断`DeletionTimestamp != nil`.

为了将自定义资源加入API, 需要在`pkg/schemas/management.cattle.io/v3/schema.go`中进行schema的初始化.

`pkg/api/norman/server/managementstored/setup.go`创建自定义资源, 新建store

norman server: `pkg/api/norman/server`

上下文初始化: `pkg/types/config/context.go`

apis/management.cattle.io/v3中修改了zz_generated_register.go, 新增了registry三个go文件.

 generated/controllers/management.cattle.io/v3中修改了interface.go, 新增了registry.go文件



# 旧版

### 生成自定义资源脚手架代码

- 先pull `rancher/types`到`$GOPATH/src/github.com/rancher`目录下
- 然后在`apis/management.cattle.io/v3`目录下创建自定义资源文件并在文件中定义自定义资源结构
- 然后在`apis/management.cattle.io/v3/schema`目录下的schema.go文件中添加对该自定义资源的初始化声明
- 最后执行`GO111MODULE=off go generate`生成自定义资源的相关代码(注意一定要关闭go module模式)
- 最后在rancher项目中的`go.mod`中添加`replace github.com/rancher/types => /home/xshrim/gopath/src/github.com/rancher/types`以使用本地`rancher/types`包

### 整合到rancher中

- 在`pkg/controllers/management`目录下创建自定义资源对应的目录, 并在该目录中编写自定义控制器的注册代码和控制逻辑代码
- 在`pkg/controllers/management/controller.go`文件中注册自定义控制器
- 在`pkg/api/server/managementstored/setup.go`文件中声明需要自动创建的自定义资源并构建资源操作方式(本地store机制)
- 在`pkg/api/store`目录下创建自定义资源对应的store目录, 在其中编写该资源的读写更新删除方法以及格式化, 验证等规则

### 添加资源权限

- 在`app/role_data.go`中添加不同角色对自定义资源的权限

### 支持独立API路径

- 在`pkg/wrangler/context.go`文件中向wranglerContext增加`github.com/rancher/types/apis/management.cattle.io/v3`的Management字段
- 在`/pkg/steve/setup.go`文件中增加独立API路由, 并编写handler(handler中可根据需要使用wranglerContext中的management)

