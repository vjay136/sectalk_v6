package com.eaglesecurity.sectalk;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import com.google.androidbrowserhelper.trusted.LauncherActivity;

public final class SecTalkActivity extends LauncherActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // An explicit intent can bypass manifest filters. Forward only the validated URL,
        // never caller-supplied extras, grants, or content.
        Intent incoming = getIntent();
        String link = incoming == null ? null : incoming.getDataString();
        Intent clean = new Intent(Intent.ACTION_MAIN);
        clean.setClass(this, SecTalkActivity.class);
        clean.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (incoming != null && Intent.ACTION_VIEW.equals(incoming.getAction())
                && SecTalkLink.isAllowed(link, getString(R.string.launch_url))) {
            clean.setAction(Intent.ACTION_VIEW);
            clean.setData(Uri.parse(link));
        }
        setIntent(clean);
        super.onCreate(savedInstanceState);
    }
}
