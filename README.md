# RequestAndResponseModifier


### What is it
This is a very simple Burp extension that allows you to modify Requests and Responses in Burp in a Python environment.

### When to use
This type of extension is very useful when you want to manipulate the requests in a complex way (such as calculate a signature over the request, (d)encrypt part of it, etc).

### How to use
Just add your code in the `onRequest` and/or `onResponse` methods.  
The  *request* and *response* parameters are strings.  
**Be aware:**
You will not see the modified version of the request on Burp's history.  
Use the `print` function inside `onRequest` to get some visibility.

### Scope
By default, the only requests that are affected are the ones in scope, if you want to modify all of them, set *onlyModifyInScopeDomains* to false:
```python
onlyModifyInScopeDomains = False
```
