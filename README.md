## command to zip nd upload this lamba funct to testing and prod

```
zip -r stripe-webhook.zip * && aws lambda update-function-code --function-name InboundWebhook-Lambda-f46a9d70-614c-11ed-bec0-0a1426bd6fa4 --zip-file fileb://stripe-webhook.zip && aws lambda update-function-code --function-name InboundWebhook-Lambda-14b0aaf0-614a-11ed-8049-02e2fd499592 --zip-file fileb://stripe-webhook.zip
```


- NOTE that ots in this repo is compilied for x86 !! 


##### KEYS
- keys are only gen in checkout stage. they are inserted into checkout_users
- paid users can only pull from checkout_users


## TODO

- we let inifite trials rn 