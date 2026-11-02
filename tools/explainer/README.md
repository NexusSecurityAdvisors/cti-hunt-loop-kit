# Explainer video source

`scenes.html` draws every frame from a pure `render(scene, t)` function, so the video is reproducible.
`render.js` steps through each scene at 30 fps, pipes JPEG frames into ffmpeg (one H.264 file per scene),
and the scenes are joined without re-encoding.

```bash
cd tools/explainer
node render.js     # needs Node, Playwright (Chromium) and ffmpeg
for i in 1 2 3 4 5 6 7; do echo "file 'scene$i.mp4'"; done > list.txt
ffmpeg -f concat -safe 0 -i list.txt -c copy -movflags +faststart ../../assets/hunt-loop-explainer.mp4
```

Edit the text or timings in `scenes.html` (`window.DUR` holds scene lengths), then re-render.
