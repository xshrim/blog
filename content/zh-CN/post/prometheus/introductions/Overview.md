##### 一、什么是prometheus？
[Prometheus](https://github.com/prometheus)是一个最初在[SoundCloud](https://soundcloud.com/)上构建的开源系统监视和警报工具包。自2012年成立以来，许多公司和组织都采用了Prometheus，该项目拥有非常活跃的开发者和用户[社区](https://prometheus.io/community/)。 它现在是一个独立的开源项目，可以独立于任何公司进行维护。 为了强调这一点，并阐明项目的治理结构，Prometheus于2016年加入[Cloud Native Computing Foundation](https://www.cncf.io/)，作为继[Kubernetes](https://kubernetes.io/)之后的第二个托管项目。

有关Prometheus的更详细概述，请参阅[媒体](https://prometheus.io/docs/introduction/media/)部分链接的资源。

###### 1.1 特征
Prometheus的主要特征有：
- 多维度数据[模型](https://prometheus.io/docs/concepts/data_model/)-由指标键值对标识的时间序列数据组成
- PromQL，一种[灵活的查询语言](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- 不依赖分布式存储; 单个服务器节点是自治的
- 以HTTP方式，通过`pull`模式拉取时间序列数据
- 支持通过中间网关[推送时间序列数据](https://prometheus.io/docs/instrumenting/pushing/)
- 通过服务发现或者静态配置，来发现目标服务对象
- 支持多种多样的图表和界面展示

###### 1.2 组件
Prometheus生态包括了很多组件，它们中的一些是可选的：
- [Prometheus server](https://github.com/prometheus/prometheus)，用于抓取和存储时间序列数据
- 用于检测应用程序代码的[`client libraries`](https://prometheus.io/docs/instrumenting/clientlibs/)
- 用于支持短期`jobs`的[`push`网关](https://github.com/prometheus/pushgateway)
- 针对`HAProxy`，`StatsD`，`Graphite`等服务的特定[`exporters`](https://prometheus.io/docs/instrumenting/exporters/) 
- [预警管理器](https://github.com/prometheus/alertmanager)来管理预警
- 各种支持工具

多数Prometheus组件是[Go语言](https://golang.org/)写的，这使得这些组件很容易编译和部署。

###### 1.3 架构
下面这张图说明了Prometheus的整体架构，以及生态中的一些组件作用:
![Prometheus Arhitecture](https://prometheus.io/assets/architecture.svg)

Prometheus可以直接通过目标拉取数据，或者间接地通过中间网关拉取数据。它在本地存储抓取的所有数据，并通过规则从现有数据中聚合记录新的时间序列或者产生预警，[`Grafana`](https://grafana.com/)和其他API可用于可视化收集的数据。

##### 二、什么时候适用？
Prometheus适用于记录任何纯数字时间序列。 它适用于以机器为中心的监控以及高度动态的面向服务架构的监控。 在微服务的世界中，Prometheus的多维度数据收集和查询非常强大。

Prometheus是为服务的可靠性而设计的，当服务出现故障时，它可以使你快速定位和诊断问题。 每个Prometheus服务器都是独立的，不依赖于网络存储或其他远程服务。 当基础架构的其他部分损坏时，您可以依赖它，并且您不需要设置大量的基础架构来使用它。

##### 三、什么时候不适用？
Prometheus重视可靠性。 即使在故障情况下，您也可以随时查看有关系统的可用统计信息。 如果您需要100％的准确度，例如按请求计费，Prometheus不是一个好的选择，因为收集的数据可能不够详细和完整。 在这种情况下，您最好使用其他系统来收集和分析数据以进行计费，并使用Prometheus进行其余监控。

> 译文:https://prometheus.io/docs/introduction/overview/
