```shell
./network.sh down
./network.sh up createChannel 
./network.sh deployCC -ccn DTModeling -ccp DTModeling -ccl go
```

```shell
rm -rf organizations
cp -R ../fabric-samples/test-network/organizations .
```

```shell
./tape -c createDID.yaml -n 500
```
