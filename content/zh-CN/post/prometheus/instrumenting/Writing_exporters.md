如果您正在检测自己的代码，则应遵循如何使用[Prometheus客户端库检测代码的一般规则](https://prometheus.io/docs/practices/instrumentation/)。 从其他监控或仪表系统中获取指标时，事情往往不是那么黑白。

本文档包含编写导出器或自定义收集器时应考虑的事项。 所涉及的理论也将对那些从事直接仪器工作的人感兴趣。

如果您正在撰写出口商并且对此处的任何内容不清楚，请通过IRC（Freenode上的#prometheus）或[邮件列表](https://prometheus.io/community/)与我们联系。

##### 一、可维护性和Purity
在编写导出器时，您需要做出的主要决定是您愿意投入多少工作来获得完美的指标。

如果有问题的系统只有少数几乎没有变化的指标，那么让一切都完美是一个简单的选择，[HAProxy exporter](https://github.com/prometheus/haproxy_exporter)就是一个很好的例子。

另一方面，如果您在系统有数百个经常随新版本更改的指标时试图让事情变得完美，那么您已经为自己签了很多正在进行的工作。 MySQL出口商正处于这一端。

[node exporter](https://github.com/prometheus/node_exporter)是这些的混合，复杂性因模块而异。 例如，`mdadm`收集器手工解析文件并公开专门为该收集器创建的度量标准，因此我们也可以正确地获取指标。 对于`meminfo`收集器，结果因内核版本而异，因此我们最终只进行了足够的转换以创建有效的度量标准。

##### 二、配置
使用应用程序时，您应该瞄准一个导出器，除了告诉应用程序在哪里之外，用户不需要自定义配置。您可能还需要提供过滤掉某些指标的功能，如果它们在大型设置上过于精细和昂贵，例如[HAProxy exporter](https://github.com/prometheus/haproxy_exporter)允许过滤每服务器统计数据。同样，默认情况下可能会禁用昂贵的指标。

在使用其他监控系统，框架和协议时，您通常需要提供额外的配置或自定义，以生成适合Prometheus的指标。在最佳情况下，监控系统具有与Prometheus类似的足够数据模型，您可以自动确定如何转换指标。这是[Cloudwatch](https://github.com/prometheus/cloudwatch_exporter)，[SNMP](https://github.com/prometheus/snmp_exporter)和[collectd](https://github.com/prometheus/collectd_exporter)的情况。最多，我们需要能够让用户选择他们想要提取的指标。

在其他情况下，系统的指标完全不标准，具体取决于系统和底层应用程序的使用情况。在这种情况下，用户必须告诉我们如何转换指标。 [JMX exporter](https://github.com/prometheus/jmx_exporter)是这里最糟糕的攻击者，[Graphite](https://github.com/prometheus/graphite_exporter)和[StatsD](https://github.com/prometheus/statsd_exporter)导出器也需要配置来提取标签。

确保导出器在没有配置的情况下开箱即用，并根据需要提供一系列用于转换的示例配置。

YAML是标准的Prometheus配置格式，默认情况下所有配置都应使用YAML。

##### 三、度量指标
######  3.1 命名
遵循[度量指标最佳实践](https://prometheus.io/docs/practices/naming)

通常，度量标准名称应该允许熟悉Prometheus但不熟悉特定系统的人对度量标准的含义做出很好的猜测。名为`http_requests_total`的度量标准不是非常有用 - 这些是在它们进入时，在某些过滤器中还是在它们到达用户代码时进行测量的？而`requests_total`则更糟糕，请求的类型是什么？

使用直接检测，给定度量应该只存在于一个文件中。因此，在出口商和收集者中，度量标准应该适用于一个子系统并相应地命名。

除非编写自定义收集器或导出器，否则不应以程序方式生成度量标准名称。

应用程序的度量标准名称通常应以导出器名称为前缀，例如： `haproxy_up`。

度量标准必须使用基本单位（例如秒，字节），并将它们转换为对图形工具更具可读性的东西。无论您最终使用哪些单位，度量标准名称中的单位必须与使用的单位相匹配。同样，暴露比率，而不是百分比。更好的是，为比率的两个组成部分中的每一个指定一个计数器。

度量标准名称不应包含与其一起导出的标签，例如`by_type`，因为如果标签聚合在一起就没有意义。

一个例外是当您通过多个指标导出具有不同标签的相同数据时，在这种情况下，这通常是区分它们的最佳方式。对于直接检测，只有在导出单个度量标准时才会出现这种情况，并且所有标记都具有过高的基数。

Prometheus指标和标签名称以`snake_cas`e编写。将`camelCase`转换为`snake_case`是可取的，尽管这样做自动并不总能为`myTCPExample`或`isNaN`之类的东西产生好的结果，所以有时候最好将它们保持原样。

公开的度量标准不应包含冒号，这些是为聚合时使用的用户定义的记录规则保留的。

只有`[a-zA-Z0-9_]`在度量标准名称中有效，任何其他字符都应该清理为下划线。

`_sum`，`_count`，`_bucket`和`_total`后缀由Summaries，Histograms和Counters使用。除非您正在生产其中之一，否则请避免使用这些后缀。

`_total`是计数器的约定，如果您使用的是COUNTER类型，则应使用它。

`process_`和`scrape_`前缀是保留的。如果它们遵循匹配的语义，可以在这些上添加自己的前缀。例如，Prometheus `scrape_duration_seconds`表示刮除了多长时间，最好还有一个以导出器为中心的指标，例如： `jmx_scrape_duration_seconds`，说明特定出口商花了多长时间做这件事。对于可以访问PID的进程统计数据，Go和Python都提供了可以为您处理此问题的收集器。一个很好的例子是HAProxy导出器。

如果您有成功的请求计数和失败的请求计数，则公开此请求的最佳方式是作为总请求的一个度量标准和针对失败请求的另一个度量标准。这使得计算故障率变得容易。不要将一个度量标准与失败或成功标签一起使用。类似地，对于缓存的命中或未命中，最好有一个指标用于总计，另一个指标用于命中。

考虑使用监控的人员对度量标准名称执行代码或Web搜索的可能性。如果这些名称非常完善且不太可能在人们习惯于这些名称的领域之外使用，例如SNMP和网络工程师，那么将它们保留为原样可能是一个好主意。此逻辑不适用于所有导出器，例如，MySQL导出器度量标准可能被各种人使用，而不仅仅是DBA。具有原始名称的HELP字符串可以提供与使用原始名称相同的大部分好处。

###### 3.2 labels
阅读关labels标签的建议,详见[advice](https://prometheus.io/docs/practices/instrumentation/#things-to-watch-out-for)

避免`type`作为标签名称，它太通用，通常没有意义。您还应该尝试尽可能避免可能与目标标签冲突的名称，例如`region`，`zone`，`cluster`，`availability_zone`，`az`，`datacenter`，`dc`，`owner`，`customer`，`stage`，`service`，`environment`和`env`。但是，如果这是应用程序调用某些资源的内容，最好不要通过重命名来引起混淆。

避免将事物放入一个指标中的诱惑，因为它们共享一个前缀。除非您确定某些指标有意义，否则多个指标更安全。

标签`le`对于直方图具有特殊含义，对于`Summaries`具有`quantile `。一般避免这些标签。

读/写和发送/接收最好作为单独的指标，而不是标签。这通常是因为您一次只关心其中一个，并且更容易以这种方式使用它们。

经验法则是，在求和或平均时，一个度量应该是有意义的。还有另一个案例出现在导出器中，而这些数据基本上是表格式的，否则将要求用户对度量标准名称的正则表达式可用。考虑一下主板上的电压传感器，而在它们之间进行数学计算是没有意义的，将它们放在一个指标中而不是每个传感器有一个指标是有意义的。度量中的所有值应该（几乎）总是具有相同的单位，例如考虑风扇速度是否与电压混合在一起，并且您无法自动分离它们。

不要做这些：
```
my_metric{label=a} 1
my_metric{label=b} 6
**my_metric{label=total} 7**
```

或者
```
my_metric{label=a} 1
my_metric{label=b} 6
**my_metric{} 7**
```

对于那些对你的指标进行`sum()`的人来说，前者会中断，后者会破坏总和并且很难处理。一些客户端库（例如Go）将主动尝试阻止您在自定义收集器中执行后者，并且所有客户端库都应该阻止您使用直接检测来执行后者。永远不要做其中任何一个，而是依靠Prometheus聚合。

如果您的监控公开这样的总数，则减去总数。如果由于某种原因必须保留它，例如总数包括不单独计算的内容，请使用不同的度量标准名称。

仪表标签应该是最小的，每个额外的标签是用户在编写PromQL时需要考虑的标签。因此，避免使用可以移除的仪器标签而不影响时间序列的唯一性。可以通过信息度量添加有关度量标准的其他信息，例如，请参阅下面的如何处理版本号。

但是，在某些情况下，预计几乎所有度量标准的用户都需要其他信息。如果是这样，添加非唯一标签而不是信息指标是正确的解决方案。例如，mysqld_exporter的`mysqld_perf_schema_events_statements_total`的摘要标签是完整查询模式的散列，足以实现唯一性。但是，如果没有人类可读的`digest_text`标签，它几乎没用，对于长查询，它只包含查询模式的开头，因此不是唯一的。因此，我们最终得到了人类的`digest_text`标签和唯一性的摘要标签。

###### 3.3 目标标签，非静电抓取
如果您发现自己想要将相同的标签应用于所有指标，请停止。

通常有两种情况出现。

第一个是针对某些标签，对于诸如软件的版本号之类的指标而言是有用的。相反，请使用https://www.robustperception.io/how-to-have-labels-for-machine-roles/中描述的方法。

第二种情况是标签实际上是目标标签。这些是区域，群集名称等等，它们来自您的基础结构设置而不是应用程序本身。应用程序并不是说它适合您的标签分类标准，而是运行Prometheus服务器进行配置的人员，监视同一应用程序的不同人员可能会给它指定不同的名称。

因此，通过您正在使用的任何服务发现，这些标签属于普罗米修斯的刮擦配置。也可以在这里应用机器角色的概念，因为它可能是至少有些人抓取它的有用信息。。

###### 3.4 类型
您应该尝试将指标的类型与Prometheus类型相匹配。 这通常意味着计数器和仪表。 `_coun`t和`_sum`的摘要也比较常见，有时你会看到分位数。 直方图很少见，如果您遇到直方图，请记住曝光格式会显示累积值。

通常情况下，指标的类型并不明显，特别是如果您自动处理一组指标。 一般来说，UNTYPED是一个安全的默认值。

计数器不能下降，所以如果你有一个来自另一个可以递减的仪器系统的计数器类型，例如Dropwizard指标那么它不是一个计数器，它就是一个指标。 UNTYPED可能是在那里使用的最佳类型，因为如果将GAUGE用作计数器，它将会产生误导。

###### 3.5 帮助文档
当您转换指标时，用户能够追溯到原始内容以及导致该转换的规则正在发挥作用。 将收集器或导出器的名称，应用的任何规则的ID以及原始度量的名称和详细信息放入帮助字符串中将极大地帮助用户。

普罗米修斯不喜欢一个具有不同帮助字符串的指标。 如果您正在制作其他许多指标，请选择其中一个指标放入帮助字符串。

例如，SNMP导出器使用OID，JMX导出器放入示例mBean名称。 HAProxy导出器具有手写字符串。 节点导出器还有各种各样的示例

###### 3.6 放弃无用的统计数据
一些仪器系统暴露1m，5m，15m速率，自应用程序启动以来的平均速率（例如，这些在Dropwizard度量中称为`mean`）以及最小值，最大值和标准偏差。

这些都应该被删除，因为它们不是很有用并且增加了混乱。 普罗米修斯可以自己计算费率，通常更准确，因为暴露的平均值通常呈指数衰减。 你不知道计算最小值或最大值的时间，标准偏差在统计上是无用的，如果你需要计算它，你总是可以暴露平方和，`_sum`和`_count`。

分位数有相关问题，您可以选择删除它们或将它们放在摘要中。

###### 3.7 .字符串
许多监控系统没有标签，而是执行`my.class.path.mymetric.labelvalue1.labelvalue2.labelvalue3`之类的操作。

Graphite和StatsD导出器共享一种使用小型配置语言转换这些内容的方法。 其他出口商也应该这样做。 转换目前仅在Go中实现，并且可以从被分解到单独的库中获益。。

##### 四、Collectors
为导出器实现收集器时，不应使用通常的直接检测方法，然后更新每个scrape上的度量标准。

而是每次创建新的指标。在Go中，这是使用`Update()`方法中的[MustNewConstMetric](https://godoc.org/github.com/prometheus/client_golang/prometheus#MustNewConstMetric)完成的。对于Python，请参阅https://github.com/prometheus/client_python#custom-collectors，对于Java，在collect方法中生成List <MetricFamilySamples>，请参阅[StandardExports.java](https://github.com/prometheus/client_java/blob/master/simpleclient_hotspot/src/main/java/io/prometheus/client/hotspot/StandardExports.java)以获取示例。

原因是双重的。首先，两个擦除可能同时发生，并且直接检测使用有效的文件级全局变量，因此您将获得竞争条件。其次，如果标签值消失，它仍然会被导出。

通过直接仪器检测出口商本身很好，例如传输的总字节数或导出器在所有擦除中执行的调用。对于黑盒出口商和SMNP出口商等出口商而言，这些出口商并未绑定到单个目标，这些出口商应仅在vanilla    `/metrics`调用上公开，而不是在特定目标的scrape上公开。

###### 4.1 关于获取度量指标本身
有时，您希望导出与刮擦有关的指标，例如花费的时间或处理的记录数。

这些应该作为计量器公开，因为它们是关于事件，scrape和以导出器名称为前缀的度量标准名称，例如`jmx_scrape_duration_seconds`。 通常情况下会排除`_exporter`，如果导出器也可以用作收集器，那么一定要排除它。

###### 4.2 硬件，进程度量指标
许多系统（例如Elasticsearch）都会公开机器指标，例如CPU，内存和文件系统信息。 由于节点导出器在Prometheus生态系统中提供这些，因此应删除此类指标。

在Java世界中，许多检测框架都公开了进程级和JVM级统计信息，例如CPU和GC。 Java客户端和JMX导出器已经通过DefaultExports.java以首选形式包含这些，因此也应该删除它们。

与其他语言和框架类似。

##### 五、部署
每个导出器应该只监视一个实例应用程序，最好是位于同一台机器旁边。这意味着对于您运行的每个HAProxy，您都运行`haproxy_exporter`进程。对于具有Mesos工作程序的每台计算机，如果计算机同时具有两者，则在其上运行Mesos导出程序，并为主计算机运行另一个计算机。

这背后的理论是，对于直接仪器而言，这就是你正在做的事情，而我们正努力在其他布局中尽可能地接近它。这意味着所有服务发现都在Prometheus中完成，而不是在出口商中完成。这也有一个好处，即Prometheus具有允许用户使用blackbox导出器探测您的服务所需的目标信息。

有两个例外：

第一个是在应用程序旁边运行，您的监控完全没有意义。 SNMP，blackbox和IPMI导出器就是其中的主要示例。作为设备的IPMI和SNMP导出器通常是黑盒子，因此无法运行代码（尽管如果你可以在它们上运行节点导出器而不是更好），而黑盒子导出器你正在监视类似于DNS名称，也没有什么可以运行。在这种情况下，普罗米修斯仍然应该进行服务发现，并传递要刮的目标。有关示例，请参阅blackbox和SNMP导出器。

请注意，目前只能使用Go，Python和Java客户端库编写此类导出器。

第二个例外是你从一个系统的随机实例中提取一些统计数据而不关心你正在谈论哪一个。考虑一组MySQL副本，您希望针对数据运行一些业务查询，然后导出。让一个使用您通常的负载平衡方法与一个副本通信的导出器是最安全的方法。

当您使用master-election监视系统时，这不适用，在这种情况下，您应该单独监视每个实例并处理Prometheus中的“masterness”。这是因为并不总是只有一个主人，并且改变目标在普罗米修斯的脚下会导致奇怪。

###### 5.1 调度
只有当Prometheus擦除它们时才会从应用程序中提取度量标准，出口商不应该根据自己的计时器执行刮擦。 也就是说，所有擦除应该是同步的。

因此，您不应该在您公开的指标上设置时间戳，让普罗米修斯负责。 如果您认为需要时间戳，那么您可能需要使用Pushgateway。

如果度量标准的检索特别昂贵，即花费超过一分钟，则可以对其进行缓存。 这应该在`HELP`字符串中注明。

Prometheus的默认刮擦超时为10秒。 如果您的导出程序可能超出此范围，则应在用户文档中明确说明。

###### 5.2 推送
某些应用程序和监视系统仅推送指标，例如StatsD，Graphite和collectd。

这里有两个考虑因素。

首先，你何时到期指标？收集和与Graphite交谈的事情都会定期导出，当它们停止时我们想要停止公开指标。 Collectd包含一个到期时间，所以我们使用它，Graphite不是，所以它是出口商的旗帜。

StatsD有点不同，因为它处理的是事件而不是指标。最好的模型是在每个应用程序旁边运行一个导出器，并在应用程序重新启动时重新启动它们，以便清除状态。

其次，这类系统倾向于允许您的用户发送增量或原始计数器。您应该尽可能地依赖原始计数器，因为这是普通的普罗米修斯模型。

对于服务级别指标，例如服务级批处理作业，您应该让您的导出器进入Pushgateway并在事件发生后退出，而不是自己处理状态。对于实例级批量指标，尚无明确的模式。选项是滥用节点导出器的文本文件收集器，依赖于内存状态（可能最好，如果您不需要持续重新启动）或实现与文本文件收集器类似的功能。

###### 5.3 抓取失败
目前有两种模式用于失败的抓取，您正在与之交谈的应用程序没有响应或有其他问题。

第一种是返回5xx错误。

第二个是有一个 `myexporter_up`，例如 `haproxy_up`，值为0或1的变量，具体取决于刮擦是否有效。

后者是更好的地方，即使是一个失败的scrape，你仍然可以获得一些有用的指标，例如提供流程统计数据的HAProxy导出器。 前者对于用户来说更容易处理，因为按照通常的方式工作，尽管您无法区分导出器关闭和应用程序关闭。

###### 5.4 登录页面
如果访问`http://yourexporter/`有一个带有导出器名称的简单HTML页面，以及指向`/metrics`页面的链接，则对用户来说更好。

###### 5.5 端口
用户可能在同一台计算机上有许多导出器和Prometheus组件，因此为了使每个组件具有唯一的端口号。

https://github.com/prometheus/prometheus/wiki/Default-port-allocations是我们跟踪它们的地方，这是可公开编辑的。

在开发出口商时，请随意抓住下一个免费端口号，最好在公开宣布之前。 如果您尚未准备好发布，请将您的用户名和WIP设置为好。

这是一个注册表，使我们的用户的生活更轻松，而不是致力于开发特定的出口商。 对于内部应用程序的导出器，我们建议使用默认端口分配范围之外的端口。


##### 六、发布
一旦您准备好向全世界宣布您的`exporter `，请通过电子邮件发送邮件列表并发送PR以将其添加到可用`exporter `[列表](https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exporters.md)中。

> 译文：https://prometheus.io/docs/instrumenting/clientlibs/