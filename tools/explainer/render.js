const { chromium } = require('playwright');
const { spawn } = require('child_process');
const fs = require('fs');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1280, height: 720 } });
  await p.goto('file://' + __dirname + '/scenes.html'); await p.evaluate(() => document.fonts.ready);
  const DUR = await p.evaluate(() => window.DUR);
  for (const s of Object.keys(DUR).map(Number)) {
    const n = Math.round(DUR[s] * 30), tmp = `scene${s}.part.mp4`, out = `scene${s}.mp4`;
    const ff = spawn('ffmpeg', ['-y','-loglevel','error','-f','image2pipe','-framerate','30','-c:v','mjpeg','-i','-',
      '-c:v','libx264','-preset','slow','-crf','20','-pix_fmt','yuv420p','-r','30','-movflags','+faststart', tmp]);
    for (let i = 0; i < n; i++) {
      await p.evaluate(([s,t]) => render(s,t), [s, i/30]);
      const buf = await p.screenshot({ type: 'jpeg', quality: 92 });
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
    }
    ff.stdin.end();
    const code = await new Promise(r => ff.on('close', r));
    if (code !== 0) throw new Error(`scene ${s} failed`);
    fs.renameSync(tmp, out); console.log(`scene ${s}: ${n} frames`);
  }
  await b.close();
})();
