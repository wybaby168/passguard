# PassGuard JMH 基线

```bash
mvn -pl passguard-benchmarks -am package
java -jar passguard-benchmarks/target/passguard-benchmarks.jar
```

发布前在固定 JDK、固定 CPU 配额和空闲机器上保存 JSON 结果，与上一正式版本比较。
`encrypt128`、`decrypt128` 或 `generatePassword` 的吞吐中位数下降超过 15% 时停止发布并分析。
密码哈希是刻意的慢操作，不与 AES-GCM 吞吐使用同一门槛。
