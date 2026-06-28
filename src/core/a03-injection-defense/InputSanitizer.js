const profiles = {
  strict: {
    stripTags: true,
    stripEventHandlers: true,
    stripScriptProtocols: true
  },
  moderate: {
    stripTags: false,
    stripEventHandlers: true,
    stripScriptProtocols: true
  }
};

export class InputSanitizer {
  constructor(profile = "strict") {
    this.profile = profiles[profile] || profiles.strict;
  }

  sanitizeHTML(input) {
    let output = String(input || "");
    output = output.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
    if (this.profile.stripTags) {
      output = output.replace(/<[^>]+>/g, "");
    }
    if (this.profile.stripEventHandlers) {
      output = output.replace(/\son[a-z]+\s*=\s*(["']).*?\1/gi, "");
      output = output.replace(/\son[a-z]+\s*=\s*[^\s>]+/gi, "");
    }
    if (this.profile.stripScriptProtocols) {
      output = output.replace(/javascript\s*:/gi, "");
    }
    return output;
  }
}