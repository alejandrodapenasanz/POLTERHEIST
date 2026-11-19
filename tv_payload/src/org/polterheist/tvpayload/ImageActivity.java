package org.polterheist.tvpayload;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.media.MediaPlayer;
import android.os.Bundle;
import android.os.Handler;
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
    private View curtain;
    private TextView scheduleStatus;
    private final Handler timer = new Handler();
    private long next = 0, interval = 0, imageMillis = 10000, hideAt = 0;
    private boolean scheduled = false, active = false, fired = false, ready = false;
    private final Runnable clock = new Runnable() {
        @Override public void run() {
            long now = System.currentTimeMillis();
            if (ready) {
                if (active && video == null && interval > 0 && now >= hideAt) hide();
                if (!active && (!fired || interval > 0) && now >= next) {
                    active = true; fired = true; hideAt = now + imageMillis;
                    curtain.setVisibility(View.GONE);
                    if (interval > 0) next += ((now - next) / interval + 1) * interval;
                    if (video != null) { video.seekTo(0); video.start(); }
                }
                if (active && interval > 0 && now >= next) next += ((now - next) / interval + 1) * interval;
                scheduleStatus.setText(active ? "" : "Next: " + new java.util.Date(next) + " | Back: cancel");
            }
            timer.postDelayed(this, 250);
        }
    };

    private void hide() {
        active = false;
        if (curtain != null) curtain.setVisibility(View.VISIBLE);
        if (video != null) video.pause();
    }

    private void attach(View view) {
        FrameLayout frame = new FrameLayout(this);
        frame.setBackgroundColor(Color.BLACK);
        frame.addView(view, new FrameLayout.LayoutParams(-1, -1, Gravity.CENTER));
        // Keep VideoView's surface alive so it can prepare while waiting. Hiding
        // the SurfaceView itself would prevent onPrepared on some Android TVs.
        curtain = new View(this);
        curtain.setBackgroundColor(Color.BLACK);
        curtain.setVisibility(scheduled ? View.VISIBLE : View.GONE);
        frame.addView(curtain, new FrameLayout.LayoutParams(-1, -1));
        scheduleStatus = new TextView(this);
        scheduleStatus.setTextColor(Color.LTGRAY);
        frame.addView(scheduleStatus, new FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM));
        setContentView(frame);
    }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        try (InputStream input = getAssets().open("schedule.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] chunk = new byte[1024];
            int size;
            while ((size = input.read(chunk)) != -1) bytes.write(chunk, 0, size);
            JSONObject schedule = new JSONObject(bytes.toString("UTF-8"));
            next = schedule.getLong("start_at");
            interval = schedule.getLong("every_ms");
            imageMillis = schedule.getLong("image_ms");
            scheduled = true;
        } catch (java.io.FileNotFoundException absent) {
            // Older/immediate packages have no schedule.
        } catch (Exception error) { showError(); return; }
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
            attach(view);
            ready = true;
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
        video = new VideoView(this);
        attach(video);
        video.setOnPreparedListener(new MediaPlayer.OnPreparedListener() {
            @Override public void onPrepared(MediaPlayer player) {
                player.setLooping(!scheduled || interval == 0);
                ready = true;
                if (!scheduled) video.start();
            }
        });
        video.setOnCompletionListener(new MediaPlayer.OnCompletionListener() {
            @Override public void onCompletion(MediaPlayer player) {
                if (scheduled && interval > 0) hide();
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
        timer.removeCallbacks(clock);
        if (video != null) video.pause();
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (scheduled) { timer.removeCallbacks(clock); timer.post(clock); }
        if (video != null && (!scheduled || active)) video.start();
    }

    @Override
    protected void onDestroy() {
        timer.removeCallbacks(clock);
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
