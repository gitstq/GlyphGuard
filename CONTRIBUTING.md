# 贡献指南 | Contributing

感谢你考虑为 **GlyphGuard** 做出贡献！本工具坚持「零依赖、纯标准库」原则，所有贡献都应遵循这一约束。

## 行为准则

- 保持纯标准库实现，不引入任何第三方依赖（`requirements` 必须为空）。
- 提交信息遵循 Angular 规范：`feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `chore:`。
- 新增功能请同步补充单元测试与文档。

## 如何添加同形字（confusable）数据

同形字数据集中在 `glyphguard/data.py`：

- 单字符映射：加入 `CONFUSABLES` 字典（`源字符 -> ASCII 基准字符`）。
- 算法化区间（全角、数学字母、带圈字母等）：加入 `ALGORITHMIC_CONFUSABLES`。
- **只收录确凿、广为人知的映射**，避免引入误报。
- 每个新增映射都应配套一条单元测试（`tests/test_data.py`、`tests/test_detect.py`）。

## 本地校验（仅语法检查，请勿本地运行项目代码）

```bash
python -m compileall -q glyphguard tests
```

完整的测试与多平台构建由 GitHub Actions 云端完成。

## 提交流程

1. Fork 并创建特性分支：`git checkout -b feat/my-feature`
2. 编写代码与测试
3. 提交：`feat: 添加 xxx 同形字映射`
4. 发起 Pull Request，CI 通过即可合并

Issues 与讨论请前往 [GitHub Issues](https://github.com/gitstq/GlyphGuard/issues)。
