// api/scripts/obfuscate.js
// ============================================
// MULTI-LAYER RUNTIME OBFUSCATION
// ============================================

const crypto = require('crypto');
const CryptoEngine = require('../../lib/crypto');
const { OBFUSCATION_LAYERS, VARIABLE_NAME_LENGTH } = require('../../lib/constants');

class Obfuscator {
  
  /**
   * Generate random variable name
   */
  static randomVar(length = VARIABLE_NAME_LENGTH) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
    const allChars = chars + '0123456789';
    let result = chars[Math.floor(Math.random() * chars.length)];
    for (let i = 1; i < length; i++) {
      result += allChars[Math.floor(Math.random() * allChars.length)];
    }
    return result;
  }
  
  /**
   * Layer 1: String encoding
   */
  static encodeStrings(source) {
    // Convert string literals to encoded form
    return source.replace(/"([^"\\]|\\.)*"/g, (match) => {
      const str = match.slice(1, -1);
      const encoded = Buffer.from(str).toString('base64');
      // For Lua: return a base64 decode expression
      return `(__DECODE__("${encoded}"))`;
    });
  }
  
  /**
   * Layer 2: Variable name randomization
   */
  static randomizeVariables(source) {
    const varMap = new Map();
    let counter = 0;
    
    // Simple pattern: replace common variable patterns
    return source.replace(/\blocal\s+(\w+)/g, (match, varName) => {
      if (!varMap.has(varName)) {
        varMap.set(varName, this.randomVar());
        counter++;
      }
      return `local ${varMap.get(varName)}`;
    });
  }
  
  /**
   * Layer 3: Control flow obfuscation
   */
  static obfuscateControlFlow(source) {
    const marker = this.randomVar(8);
    // Wrap in a complex execution path
    return `
do
  local ${marker} = (function()
    local __r = {}
    __r.__index = __r
    return setmetatable({}, {
      __call = function()
        ${source}
      end
    })
  end)()
  ${marker}()
end`;
  }
  
  /**
   * Layer 4: Anti-tamper wrapper
   */
  static antiTamperWrap(source, sessionToken, expiresAt) {
    const checkVar = this.randomVar();
    const timeVar = this.randomVar();
    const validVar = this.randomVar();
    
    return `
-- Protected Script | Session: ${sessionToken.substring(0, 8)}...
-- Tampering with this script will cause immediate termination
local ${timeVar} = os and os.time and os.time() or 0
local ${validVar} = ${Math.floor(expiresAt / 1000)}
local ${checkVar} = ${timeVar} <= ${validVar}

if not ${checkVar} then
  return error("Session expired")
end

-- Anti-debug
if rawget(_G, "debug") and debug.getinfo then
  local info = debug.getinfo(1)
  if info and info.source and info.source:find("@") then
    return error("Debug mode detected")
  end
end

${source}

-- End Protected Block`;
  }
  
  /**
   * Full obfuscation pipeline
   */
  static obfuscate(source, options = {}) {
    let result = source;
    const layers = options.layers || OBFUSCATION_LAYERS;
    const appliedLayers = [];
    
    if (layers >= 1) {
      result = this.encodeStrings(result);
      appliedLayers.push('string_encoding');
    }
    
    if (layers >= 2) {
      result = this.randomizeVariables(result);
      appliedLayers.push('variable_randomization');
    }
    
    if (layers >= 3) {
      result = this.obfuscateControlFlow(result);
      appliedLayers.push('control_flow');
    }
    
    if (options.sessionToken) {
      result = this.antiTamperWrap(
        result, 
        options.sessionToken, 
        options.expiresAt || Date.now() + 300000
      );
      appliedLayers.push('anti_tamper');
    }
    
    // Add decode helper at the top
    const decoder = `
local __DECODE__ = function(s)
  local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  s = s:gsub('[^'..b..'=]','')
  return (s:gsub('.', function(x)
    if x == '=' then return '' end
    local r,f='',(b:find(x)-1)
    for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
    return r
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
    if #x ~= 8 then return '' end
    local c=0
    for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
    return string.char(c)
  end))
end
`;
    
    result = decoder + '\n' + result;
    
    return {
      source: result,
      layers: appliedLayers,
      originalSize: Buffer.byteLength(source, 'utf8'),
      obfuscatedSize: Buffer.byteLength(result, 'utf8'),
    };
  }
}

module.exports = Obfuscator;
