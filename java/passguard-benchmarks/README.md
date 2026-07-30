# PassGuard JMH 基线

```bash
mvn -pl passguard-benchmarks -am package
java -jar passguard-benchmarks/target/passguard-benchmarks.jar
```

CI 固定使用 Ubuntu 24.04、Temurin 17.0.19，并执行 3 次一秒预热和 5 次一秒测量，
避免把 JIT 升温误判为回归。全部基准结果相对已提交基线下降超过 15% 时停止合并并分析；
失败时仍上传原始 JMH JSON，便于区分代码回归与宿主机异常。

正式发布前还应在固定 CPU 配额的空闲机器上复测，并与上一正式版本比较。
密码哈希是刻意的慢操作，不与 AES-GCM 吞吐使用同一门槛。
