# Spring Boot 配置与数据库加密

## 1. 选择 Starter

Java 8 / Spring Boot 2：

```xml
<dependency>
  <groupId>dev.flyfish</groupId>
  <artifactId>passguard-spring-boot2-starter</artifactId>
  <version>2.1.0</version>
</dependency>
```

Java 17 / Spring Boot 3 将 artifactId 换成 `passguard-spring-boot3-starter`。
数据库适配器按需添加：

```xml
<dependency>
  <groupId>dev.flyfish</groupId>
  <artifactId>passguard-crypto-jpa-jakarta</artifactId>
  <version>2.1.0</version>
</dependency>
<dependency>
  <groupId>dev.flyfish</groupId>
  <artifactId>passguard-crypto-jackson</artifactId>
  <version>2.1.0</version>
</dependency>
```

MyBatis 使用 `passguard-crypto-mybatis`；Boot 2 JPA 使用
`passguard-crypto-jpa-javax`；R2DBC 使用对应 Boot 代际的模块。任何适配器都不会
传递引入其他数据库框架。

## 2. 提供密钥

每个用途使用独立的 32 字节随机密钥：

```bash
export PASSGUARD_KEY_DATA_ACTIVE=v1
export PASSGUARD_KEY_DATA_V1='Base64 编码的 32 字节数据密钥'
export PASSGUARD_KEY_INDEX_ACTIVE=v1
export PASSGUARD_KEY_INDEX_V1='Base64 编码的 32 字节索引密钥'
export PASSGUARD_KEY_CONFIG_ACTIVE=v1
export PASSGUARD_KEY_CONFIG_V1='Base64 编码的 32 字节配置密钥'
```

密钥不得写入 Git、YAML、Properties、日志或命令行参数。也可以配置
`passguard.crypto.provider=keystore`，使用 PKCS12/JCEKS；KeyStore 密码仍必须来自
`PASSGUARD_KEYSTORE_PASSWORD` 等环境变量，或由
`passguard.crypto.key-store.password-system-property` 指定的外部 JVM 系统属性。
配置文件中只允许出现“系统属性名”，不得出现密码本身。

## 3. 加密配置文件

使用 `ConfigCryptoCli encrypt config`，从标准输入读取明文，输出：

```yaml
spring:
  datasource:
    password: ENC(PG1.v1...)
```

jasypt-spring-boot 在 PropertySource 层调用 PassGuard，所以下列三种方式都获得明文：

```java
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Value("${spring.datasource.password}")
private String password;

@ConfigurationProperties("spring.datasource")
class DataSourceProperties {
    private String password;
}
```

若密钥缺失、key id 未知、上下文不匹配或认证标签损坏，应用启动失败，不会把密文或
原始值当作明文继续运行。

## 4. 数据库字段

```java
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
class ExternalCredential {
    @Id
    private Long id;

    @Encrypted(
        keyAlias = "data",
        context = "external_credential.password"
    )
    @Column(length = 512)
    private String password;

    @BlindIndex(
        source = "password",
        keyAlias = "index",
        context = "external_credential.password_index"
    )
    @Column(length = 64)
    private String passwordIndex;
}
```

保存时数据库收到 `PG1...`，Hibernate state、MyBatis 参数或 R2DBC OutboundRow
转换完成后，实体仍保留明文；查询时在实体建立前恢复明文。`passwordIndex` 只能用于
精确等值查询，不支持 `LIKE`、范围或排序。

引入 `passguard-crypto-jackson` 后，`@Encrypted` 自动成为 write-only：
请求可以反序列化，响应 JSON 完全没有该属性。推荐仍使用独立响应 DTO，避免把实体
直接当 API 契约。

## 5. 明文迁移与轮换

默认 `passguard.crypto.read-policy=strict`，保护字段出现旧明文会立即失败。
迁移窗口可暂时改为：

```yaml
passguard:
  crypto:
    read-policy: migration
```

此模式只允许读取旧明文；所有新写入仍然加密。通过 `SecretMigrationService` 分页、
试运行和事务写回后，必须恢复 `strict`。

轮换时添加新 key id 并把 `*_ACTIVE` 指向它。新写入自动使用新密钥，历史密文仍按
自身携带的 key id 解密。`ReEncryptionService.needsReEncryption` 可筛选旧版本，
`migrate(..., true)` 先试运行，`migrate(..., false)` 再由应用事务写回；完成批量
重加密并确认无引用前，不得停用或删除旧密钥。

## 6. Actuator 与日志

Starter 在 Actuator 存在时自动增强敏感值脱敏：密码、secret、token、key 等敏感键，
以及 `PG1`、`BI1`、`ENC(PG1...)` 值都不会由配置诊断端点直接展示。实体仍不应把
受保护字段放入自动生成的 `toString()`，也不得把秘密写入日志、异常消息或指标标签。
