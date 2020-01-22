ndff-dev
===========

このリポジトリはなに？
------------------------

取得できる情報が少ないかわりに、Packetbeatよりメモリリークが起こりにくくCPU使用率が低く抑えられるいい感じのPacket Analyzer/Shipperとして開発しているndffであるが、ndff v0.1からnDPIのAPIも仕様がそれなりに変更されていて、テストをきちんと書いておきたい...

それなりにコードに手を入れることになるため、ndffのリポジトリに直接手を入れず、一旦こちらの開発用リポジトリで開発を進める。修正箇所の修正が一段落したらマージを進める。

方針
-------

IPヘッダーの抽出、TCP/UDPヘッダの抽出、フローの集約など、ndffで実装する関数は原則として関数同士の依存が出来るだけない状態にしてユニットテストをtest.cppに書きましょう。

開発用Dockerイメージの使い方
-------------------------------

```
$ docker build -t nkoneko/ndff-dev:latest -f develop/Dockerfile .
$ # ソースコードを適当に編集したら、次のコマンドでLinux上でビルドしてテストする。
$ docker run --rm --mount type=bind,src=$(pwd),target=/opt/ndff,readonly,consistency=cached nkoneko/ndff-dev:latest
```
