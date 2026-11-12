# juicebox-swift

PIN で保護された秘密データを復旧するための Swift パッケージです。`Juicebox` モジュールは、ソフトウェア realm と Noise NK を使うハードウェア realm に対応しています。

ホストアプリは realm の設定と認証トークンを `JuiceboxRecovery` に渡し、`JuiceboxHTTPTransport` を実装します。復旧は `recover(pin:transport:)` を呼び出します。

実装と互換性テストは [xchat-swift の Juicebox ターゲット](https://github.com/zunda-pixel/xchat-swift/tree/a2b630ab0568c9472e132fe63e8f3743117e8814/Sources/Juicebox) から移しました。プロトコルと Linux でのテスト手順は [docs/JUICEBOX.md](docs/JUICEBOX.md) にあります。
