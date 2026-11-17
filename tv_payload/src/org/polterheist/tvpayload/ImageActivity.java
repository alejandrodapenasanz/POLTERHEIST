package org.polterheist.tvpayload;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.media.MediaPlayer;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.VideoView;
import android.widget.FrameLayout;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import org.json.JSONObject;

/** Offline image/video player. All media bytes are packaged in the installed APK. */
public final class ImageActivity extends Activity {
    private Bitmap image;
    private VideoView video;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        try (InputStream metadata = getAssets().open("content.json")) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] bytes = new byte[1024];
            int count;
            while ((count = metadata.read(bytes)) != -1) {
                buffer.write(bytes, 0, count);
            }
            JSONObject content = new JSONObject(buffer.toString("UTF-8"));
            if ("video".equals(content.getString("kind"))) {
                playVideo();
                return;
            }
        } catch (Exception error) {
            showError();
            return;
        }
        try (InputStream stream = getAssets().open("image.jpg")) {
            image = BitmapFactory.decodeStream(stream);
            if (image == null) {
                throw new IllegalStateException("Image cannot be decoded");
            }
            ImageView view = new ImageView(this);
            view.setBackgroundColor(Color.BLACK);
            view.setScaleType(ImageView.ScaleType.FIT_CENTER);
            view.setContentDescription("TV Payload image");
            view.setImageBitmap(image);
            setContentView(view);
        } catch (Exception error) {
            showError();
        }
    }

    private void playVideo() throws Exception {
        File local = new File(getFilesDir(), "payload.mp4");
        try (InputStream input = getAssets().open("video.mp4");
                FileOutputStream output = new FileOutputStream(local)) {
            byte[] chunk = new byte[65536];
            int count;
            while ((count = input.read(chunk)) != -1) {
                output.write(chunk, 0, count);
            }
        }
        FrameLayout frame = new FrameLayout(this);
        frame.setBackgroundColor(Color.BLACK);
        video = new VideoView(this);
        frame.addView(video, new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT, Gravity.CENTER));
        setContentView(frame);
        video.setOnPreparedListener(new MediaPlayer.OnPreparedListener() {
            @Override public void onPrepared(MediaPlayer player) {
                player.setLooping(true);
                video.start();
            }
        });
        video.setOnErrorListener(new MediaPlayer.OnErrorListener() {
            @Override public boolean onError(MediaPlayer player, int what, int extra) {
                showError();
                return true;
            }
        });
        video.setVideoPath(local.getAbsolutePath());
    }

    private void showError() {
        TextView message = new TextView(this);
        message.setBackgroundColor(Color.BLACK);
        message.setTextColor(Color.WHITE);
        message.setTextSize(24);
        message.setGravity(Gravity.CENTER);
        message.setText("TV Payload: content unavailable. Send the content again from POLTERHEIST.");
        setContentView(message);
    }

    @Override
    protected void onPause() {
        if (video != null) video.pause();
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (video != null) video.start();
    }

    @Override
    protected void onDestroy() {
        if (video != null) video.stopPlayback();
        super.onDestroy();
    }

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused) {
            getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        }
    }
}
