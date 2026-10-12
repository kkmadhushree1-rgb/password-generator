(function () {
  var SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.<>?/~"
  };
  var AMBIGUOUS = "0O1lI|";
  var $ = function (id) { return document.getElementById(id); };

  // Unbiased secure random integer in [0, max)
  function randInt(max) {
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function uniq(s) { return Array.from(new Set(s.split(""))).join(""); }

  function buildPools() {
    var skip = $("ambiguous").checked;
    var excl = $("exclude").value;
    var customSym = uniq($("customSymbols").value.replace(/\s/g, ""));
    return Object.keys(SETS).filter(function (k) { return $(k).checked; }).map(function (k) {
      var chars = (k === "symbols" && customSym) ? customSym : SETS[k];
      return chars.split("").filter(function (c) {
        return !(skip && AMBIGUOUS.indexOf(c) >= 0) && excl.indexOf(c) < 0;
      }).join("");
    }).filter(function (p) { return p.length; });
  }

  function fail(text) { $("msg").textContent = text; render("", 0, false); }

  function generate() {
    var length = +$("length").value;
    var kw = Array.from($("keyword").value.replace(/\s/g, ""));
    var noRepeat = $("norepeat").checked;
    var startLetter = $("startLetter").checked;
    var pools = buildPools();
    if (!pools.length) return fail("Select at least one character type.");

    var randLen = length - kw.length;
    if (randLen < Math.max(pools.length, 6)) {
      return fail("Keyword is too long for this length. Make the password longer or the keyword shorter.");
    }
    var all = uniq(pools.join(""));
    if (noRepeat && randLen > all.length) {
      return fail("Not enough different characters to avoid repeats. Shorten the password or allow more characters.");
    }
    $("msg").textContent = "";

    var used = {};
    function pick(chars) {
      var avail = noRepeat ? chars.split("").filter(function (c) { return !used[c]; }).join("") : chars;
      if (!avail) return null;
      var c = avail[randInt(avail.length)];
      used[c] = 1;
      return c;
    }

    // One guaranteed character from each selected type, the rest from all
    var out = [];
    pools.forEach(function (p) { var c = pick(p); if (c) out.push(c); });
    while (out.length < randLen) out.push(pick(all));

    // Fisher-Yates shuffle with secure randomness
    for (var i = out.length - 1; i > 0; i--) {
      var j = randInt(i + 1);
      var t = out[i]; out[i] = out[j]; out[j] = t;
    }

    if (startLetter) {
      var letters = [];
      out.forEach(function (c, idx) { if (/[A-Za-z]/.test(c)) letters.push(idx); });
      if (!letters.length) return fail("Allow letters to use \u201CStart with a letter\u201D.");
      if (!/[A-Za-z]/.test(out[0])) {
        var k = letters[randInt(letters.length)];
        var tmp = out[0]; out[0] = out[k]; out[k] = tmp;
      }
    }

    if (kw.length) {
      var lo = (startLetter && !/[A-Za-z]/.test(kw[0])) ? 1 : 0;
      var pos = lo + randInt(out.length - lo + 1);
      out.splice.apply(out, [pos, 0].concat(kw));
    }

    // Entropy of the random part only
    var bits = 0;
    for (var n = 0; n < randLen; n++) bits += Math.log2(noRepeat ? all.length - n : all.length);

    render(out.join(""), bits, kw.length > 0);
  }

  function render(pw, bits, hasKeyword) {
    var box = $("password");
    box.textContent = "";
    Array.from(pw).forEach(function (c) {
      var s = document.createElement("span");
      if (/[0-9]/.test(c)) s.className = "d";
      else if (!/[A-Za-z]/.test(c)) s.className = "s";
      s.textContent = c;
      box.appendChild(s);
    });

    var label = "", color = "var(--weak)", pct = 0;
    if (pw) {
      if (bits < 50) label = "Weak";
      else if (bits < 75) { label = "Fair"; color = "var(--fair)"; }
      else if (bits < 100) { label = "Strong"; color = "var(--strong)"; }
      else { label = "Very strong"; color = "var(--strong)"; }
      pct = Math.min(100, (bits / 128) * 100);
    }
    $("bar").style.width = pct + "%";
    $("bar").style.background = color;
    $("strength").textContent = label;
    $("entropy").textContent = pw ? "about " + Math.round(bits) + " bits" + (hasKeyword ? " (keyword not counted)" : "") : "";
  }

  function copy() {
    var pw = $("password").textContent;
    if (!pw) return;
    var done = function () {
      $("copy").textContent = "Copied";
      setTimeout(function () { $("copy").textContent = "Copy"; }, 1500);
    };
    var fallback = function () {
      var r = document.createRange();
      r.selectNodeContents($("password"));
      var sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
      try { document.execCommand("copy"); done(); } catch (e) {}
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(pw).then(done, fallback);
    } else { fallback(); }
  }

  $("length").addEventListener("input", function () {
    $("lengthVal").textContent = this.value;
    generate();
  });
  ["lower", "upper", "digits", "symbols", "ambiguous", "startLetter", "norepeat"].forEach(function (id) {
    $(id).addEventListener("change", generate);
  });
  ["keyword", "customSymbols", "exclude"].forEach(function (id) {
    $(id).addEventListener("input", generate);
  });
  $("generate").addEventListener("click", generate);
  $("copy").addEventListener("click", copy);

  generate();
})();
