local https = require("ssl.https")
local json = require("dkjson")
  
--------load a local mock module when needed so we can easily run outside of Vera---------
luup = luup ~= nil and luup or require "luup"
------------------------------------------------------------------------------------------

--Initialize randomizer for PKCE.
math.randomseed(math.floor(os.time()))

local MYQGATEWAY_SID = "urn:macrho-com:serviceId:MyQGateway1"
local GDO_SID = "urn:upnp-org:serviceId:SwitchPower1"
local GDO_DEVICE_TYPE = "urn:schemas-upnp-org:device:SwitchPower:1"
local LAMP_SID = "urn:upnp-org:serviceId:SwitchPower1"
local LAMP_DEVICE_TYPE = "urn:schemas-upnp-org:device:BinaryLight:1"

local VERSION = "v3.0 03-28-2021"
local PLUGIN_VARS = {
  REFRESH_INTERVAL = "RefreshInterval",
  REFRESH_AFTER_CHANGE_INTERVAL = "RefreshAfterChangeInterval",
  USERNAME = "Username",
  PASSWORD = "Password",
  DEBUG_MODE = "DebugMode",
  DEBUG_MODE_TEXT = "DebugModeTxt",
  LAST_CHECK = "LastCheck",
  LAST_TRIP = "LastTrip",
  STATUS = "Status",
  NUM_DOORS = "NumDoors",
  NUM_LIGHTS = "NumLights",
  TOKEN_TIMESTAMP = "Timestamp"
}

local LOGLEVELS = {
  CRITICAL = 1, -- Critical error. Something is wrong that shouldn't happen.
  WARN = 2, -- Warning. This is something to make note of, though it's not always a problem.
  VARIABLE_CHANGE = 6, -- Variable. A UPnP Variable has changed.
  GENERAL = 10, -- General Status. There are lots of these messages to indicate something happening in the system.
  OUTBOUND_DATA = 41, -- Outgoing data going to the external devices, such as the Z-Wave dongle and Luup plugins talking to the serial/network devices.
  INCOMING_DATA = 42 -- Incoming data. (as above)
}

local PLUGIN_CONFIG = {
  FORCE_DEBUG								= false, -- overrides user configured debug_mode - normally false
	DEBUG_MODE								= true,
	USERNAME									= "",
	PASSWORD									= "",
  ACCOUNTID                 = "",
	SECURITY_TOKEN						= "",
	APPID											= "",
	NAME											= "MyQGateway",
  LAST_TOKEN_REFRESH        = os.time()-60*60*24, --yesterday by default
  MAX_TOKEN_AGE             = 3600, -- in seconds
  REFRESH_AFTER_CHANGE      = 10, -- in seconds
  REFRESH_INTERVAL          = 30, -- in seconds
  CLEAR_TASK_AFTER          = 30 -- in seconds
}


-- Found: http://forum.micasaverde.com/index.php/topic,7458.msg47733.html#msg47733
-- Probably NOT the way I want to do this but works for now
local child_id_lookup_table = {}
local child_deviceid_lookup_table = {} -- Reverses for looking up by Vera DeviceId

local TASK_ERROR = 2
local TASK_ERROR_PERM = -2
local TASK_SUCCESS = 4
local MSG_CLASS = "MyQ Gateway"
local taskHandle = -1
local MyQGatewayID = nil -- Device ID
local COOKIEJAR = {}

local UTIL = {
    
  base64encode = function (self, data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
  end,
  
	initVar = function(self, serviceId, variable, default, deviceId)
		
    if (variable == nil or serviceId == nil or default == nil) then return end
    
    if (type(default) == "boolean") then 
      default = default and "1" or "0" 
    end
    
		local val = luup.variable_get(serviceId, variable, deviceId)
		
    if (val == nil or val == "") then 
      luup.variable_set(serviceId, variable, default, deviceId) 
    end
	end,

	getFriendlyTimestamp = function(self, timestamp)
		return os.date("%a %b %d %Y, %X", timestamp)
	end,

	sanitizeText = function(self, text)
		if (PLUGIN_CONFIG.USERNAME and (PLUGIN_CONFIG.USERNAME ~= "")) then
			text = text:gsub(PLUGIN_CONFIG.USERNAME,"********")
		end
		if (PLUGIN_CONFIG.PASSWORD and (PLUGIN_CONFIG.PASSWORD ~= "")) then
			text = text:gsub(PLUGIN_CONFIG.PASSWORD,"********")
		end
		return text
	end,
  
  base64urlencode = function(self,str)
      str = str:gsub("(%+)", "-")
      str = str:gsub("(/)", "_")
      str = str:gsub("(%=)", "")
      return str
    end,
    
    shellExecute = function(self, cmd, Output)
      if (Output == nil) then Output = true end
      local file = assert(io.popen(cmd, 'r'))
      if (Output == true) then
        local cOutput = file:read('*all')
        file:close()
        return cOutput
      else
        file:close()
        return
      end
    end,
    
    buildKeyValueString = function(self, values, delimiter)
      delimiter = delimiter ~= nil and delimiter or "&"
      
      local str = ""
          for k,v in pairs(values) do
            str = str..delimiter..k.."="..v
          end
      return self:trim(str, delimiter)
    end,
    
    generateCodeVerifier = function(self, length)
    
      local charset = {}  do -- [0-9a-zA-Z]
        for c = 48, 57  do table.insert(charset, string.char(c)) end --numbers
        for c = 65, 90  do table.insert(charset, string.char(c)) end --A-Z
        for c = 97, 122 do table.insert(charset, string.char(c)) end --a-z
      end
      
      local specialChars = "-._~"
      for i = 1, #specialChars do
        local s= string.sub(specialChars, i, i)
        table.insert(charset, s)
      end
      
      local res = ""
      for _ = 1, length do
        res = res .. charset[math.random(1, #charset)]
      end
      return res
    end,
  
    startsWith = function(self, str, pattern) 
      return string.find(str, '^' .. pattern) ~= nil
    end,
    
    urldecode = function(self, url)
      local hex_to_char = function(x)
        return string.char(tonumber(x, 16))
      end

      if url == nil then
        return
      end
      url = url:gsub("+", " ")
      url = url:gsub("%%(%x%x)", hex_to_char)
      return url
    end,
    
    trim = function(self, s, trimChar)
        trimChar = trimChar ~=nil and trimChar or ' '
      if (s == nil) then return s end
      
      local l = 1
      while string.sub(s,l,l) == trimChar do
        l = l+1
      end
      local r = string.len(s)
      while string.sub(s,r,r) == trimChar do
        r = r-1
      end
      return string.sub(s,l,r)
    end,
    
    cutString = function(self, srcString, startPattern,endPattern)
      local idx = string.find(srcString, startPattern)+#startPattern
      local subStr = string.sub(srcString, idx, #srcString)
      idx = endPattern ~= nil and string.find(subStr,endPattern) or #subStr+1
      return string.sub(subStr, 1, idx-1)
    end,
    
    split = function(self, str, sep)
      local sep, fields = sep or ":", {}
      local pattern = string.format("([^%s]+)", sep)
      string.gsub(str, pattern, function(c) fields[#fields+1] = c end)
      return fields
    end,
    
    parseCookies = function(self,cookieHeaders)
      for _,v in pairs(self:split(cookieHeaders, ",")) do
        local cookieVal = self:split(v, ";")[1]
        local kv = self:split(cookieVal, "=")
        COOKIEJAR[self:trim(kv[1])] = self:trim(kv[2])
      end
      
      return self:buildKeyValueString(COOKIEJAR, ";")
      
    end,
    
    request = function(self, url, method, headers, body, logRequest, logResponse)

      headers = headers ~= nil and headers or {}

      headers["Host"] = self:split(url,"//")[2]
      headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
      headers["Accept-Language"] = "en-US,en;q=0.9"
      headers["User-Agent"]  = headers["User-Agent"] ~= nil and headers["User-Agent"] or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"

      if (logRequest == true) then
        debug(method.." "..url)
        if (headers ~= nil) then
          for k,v in pairs(headers) do
            debug(k..": "..v)
          end
        end
        if (body ~= nil) then
          debug(body)
        end
        debug("--------------------------------------------------------------------------------------------------------------------------")
      end

      local responseChunks = {}

      local success, statusCode, responseHeaders = https.request{
          url = url,
          method = method,
          headers = headers,
          source = body ~=nil and ltn12.source.string(body) or nil,
          protocol = "tlsv1_2",
          redirect = false,
          sink = ltn12.sink.table(responseChunks)
        }

      local responseContent = (responseChunks ~= nil and table.maxn(responseChunks) > 0 and table.concat(responseChunks)) or nil

      if (logResponse == true) then
        for k,v in pairs(responseHeaders) do
          debug(k..": "..v)
        end
        
        if (responseContent ~= nil) then
          debug(responseContent)
        end
        
        debug("--------------------------------------------------------------------------------------------------------------------------")
      end

      return success, statusCode, responseHeaders, responseContent
    end,
    
    debug = function(self, text, level, forced)
      if (forced == nil) then forced = false end
      if ((PLUGIN_CONFIG.DEBUG_MODE == true) or (forced == true)) then
        -- sanitize the debug text
        text = self:sanitizeText(text)
        if (#text < 7000) then
          if (level == nil) then
            luup.log((text or "NIL"), LOGLEVELS.WARN)
          else
            luup.log((text or "NIL"), level)
          end
        else
          -- split the output into multiple debug lines
          local prefix_string = ""
          local _,debug_prefix,_ = text:find("): ")
          if (debug_prefix) then
            prefix_string = text:sub(1,debug_prefix)
            text = text:sub(debug_prefix + 1)
          end
          while (#text > 0) do
            local debug_text = text:sub(1,7000)
            text = text:sub(7001)
            if (level == nil) then
              luup.log((prefix_string..(debug_text or "NIL")), LOGLEVELS.WARN)
            else
              luup.log((prefix_string..(debug_text or "NIL")),level)
            end
          end
        end
      end
    end
}

UPnP = {
	NAME = "UPnP",
	
  changeDeviceState = function(self, lul_device, lul_settings)
    local logPrefix = PLUGIN_CONFIG.NAME.."::"..self.NAME.."::changeDeviceState "
    local targetValue = lul_settings.newTargetValue
    
    if (targetValue ~= "1" and targetValue ~= "0") then 
      log(logPrefix.."Unknown state value "..targetValue.." for device "..lul_device, LOGLEVELS.ERROR)
      return 2, 0
    end
    
    local deviceFamily = lul_settings.deviceFamily
    
    if (deviceFamily == nil) then
      log(logPrefix.."Unspecified device family when requesting "..targetValue.." for device "..lul_device, LOGLEVELS.ERROR)
      return 2, 0
    end
    
    local serviceId
    if (deviceFamily == "garagedoor") then
      serviceId = GDO_SID
    elseif (deviceFamily == "lamp") then
      serviceId = LAMP_SID
    else
      log(logPrefix.."Unsupported device family ".. deviceFamily.." when requesting "..targetValue.." for device "..lul_device, LOGLEVELS.ERROR)
      return 2, 0
    end

		local myQSerialNumber = child_deviceid_lookup_table[lul_device]
		    
    debug(logPrefix.."gateway/device/family/serial/newStatus to "..MyQGatewayID.."/"..(lul_device or "NIL").. "/".. (deviceFamily or "NIL") .."/" ..(myQSerialNumber or "NIL").. "/" .. (targetValue or "NIL"))
    
    local result = MYQ_API:changeDeviceStatus(PLUGIN_CONFIG.SECURITY_TOKEN, PLUGIN_CONFIG.ACCOUNTID, myQSerialNumber, lul_device, MyQGatewayID, deviceFamily, targetValue)
		
    if (result == false) then
      log(logPrefix.."Failed calling myQ API to change status on device "..lul_device, LOGLEVELS.ERROR)
      return 2, 0
    end
    
    luup.variable_set(serviceId, PLUGIN_VARS.STATUS, tonumber(targetValue), lul_device)
    return 4, 0
	end,
  	
  setCredentials = function(self, lul_device, lul_settings)
		local Username = lul_settings.newUsername or ""
		local Password = lul_settings.newPassword or ""
		if Username ~= "" then
			luup.variable_set(MYQGATEWAY_SID,PLUGIN_VARS.USERNAME,Username,lul_device)
		end
		if Password ~= "" then
			luup.variable_set(MYQGATEWAY_SID,PLUGIN_VARS.PASSWORD,Password,lul_device)		 
		end 
		task("Please wait....Re-initializing myQ after password update.", TASK_ERROR_PERM)
		init(lul_device)
		return 4, nil
	end,

	toggleDebugMode = function(self, lul_device)
        
    PLUGIN_CONFIG.DEBUG_MODE = not PLUGIN_CONFIG.DEBUG_MODE
    
    local varValue = (PLUGIN_CONFIG.DEBUG_MODE and "1" or "0")
    local varTextValue = (PLUGIN_CONFIG.DEBUG_MODE and "ENABLED" or "DISABLED")
		task("DEBUG MODE "..varTextValue.."!",TASK_SUCCESS)
    luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.DEBUG_MODE, varValue, lul_device)
    luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.DEBUG_MODE_TEXT, varTextValue, lul_device)
      
		debug("("..PLUGIN_CONFIG.NAME.."::"..self.NAME.."::ToggleDebugMode): Debug mode now ["..(PLUGIN_CONFIG.DEBUG_MODE and "ENABLED" or "DISABLED").."].")
	end

}

function debug(text, level, forced)
    UTIL:debug(text, level, forced)
end

--Utility function to prefix MSG_CLASS to all log calls
function log(message,msgLevel)
	if (msgLevel ~= nil) then debug(message,msgLevel,true) else debug(message,nil,true) end
end

function task(text, mode)
  debug("("..PLUGIN_CONFIG.NAME.."::task): task [" .. text.."]")
  if (mode == TASK_ERROR_PERM) then
    taskHandle = luup.task(text, TASK_ERROR, MSG_CLASS, taskHandle)
  else
    taskHandle = luup.task(text, mode, MSG_CLASS, taskHandle)
    -- Clear the previous error, since they're all transient
    if (mode ~= TASK_SUCCESS) then
        luup.call_delay("clearTask", PLUGIN_CONFIG.CLEAR_TASK_AFTER, "")
    end
  end
end

local function clearTask()
  task("Clearing...", TASK_SUCCESS)
end

do 
  local BASE_URL = "https://partner-identity.myq-cloud.com"
  MYQ_API = {

    API_CONFIG = {
      NAME            = "MyQApi",
      CLIENTID        = "IOS_CGI_MYQ",
      REDIRECT_URL    = "com.myqops://ios",
      CLIENT_SECRET   = "VUQ0RFhuS3lQV3EyNUJTdw==",
      AUTHORIZE_URL   = BASE_URL.."/connect/authorize?response_type=code&state=&client_id=%s&scope=MyQ_Residential%%20offline_access&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
      TOKEN_URL       = "https://partner-identity.myq-cloud.com/connect/token",
      ACCOUNT_URL     = "https://accounts.myq-cloud.com/api/v6.0/accounts",
      DEVICES_URL     = "https://devices.myq-cloud.com/api/v5.2/Accounts/%s/Devices",
      GDO_ACTION_URL  = "https://account-devices-gdo.myq-cloud.com/api/v5.2/Accounts/%s/door_openers/%s/%s",
      LAMP_ACTION_URL = "https://account-devices-lamp.myq-cloud.com/api/v5.2/Accounts/%s/lamps/%s/%s"
    },
    
    login = function(self, userName, password)
      local logPrefix = "("..self.API_CONFIG.NAME.."::login): "
      local codeVerifier = UTIL:generateCodeVerifier(128)
      
      --Apparently SHA256 is hard in Lua so we'll have to call out to the terminal.
      local osCmd = "printf "..codeVerifier.." | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n' ' '"
      local codeChallenge = UTIL:trim(UTIL:shellExecute(osCmd), " ")
      
      --If the shell command fails, we're probably testing/debugging locally on Windows so use a pure Lua SHA module.
      --This likely never runs on Vera.
      if (codeChallenge == "") then
        local sha = require "sha2"
        debug("Using Lua to generate challenge.")
        codeChallenge = UTIL:base64urlencode(UTIL:base64encode(sha.hex2bin(sha.sha256(codeVerifier))))
      end
      
      local challengeUrl = string.format(self.API_CONFIG.AUTHORIZE_URL, self.API_CONFIG.CLIENTID, self.API_CONFIG.REDIRECT_URL, codeChallenge)
      local response, status, header, contentStr
      
      debug(logPrefix.."Code verifier: "..codeVerifier)
      debug(logPrefix.."Beginning login with PKCE challenge: "..codeChallenge)
      
      --We'll need to carry along all of the cookies we get as we trickle through the OAuth flow.
      local accumulatedCookies = ""
      
      --Follow redirects to get login URL.
      while (status == nil or status == 302) do   
        response, status, header, contentStr = UTIL:request(challengeUrl, "GET", string.len(accumulatedCookies) > 0 and {["Cookie"] = accumulatedCookies} or nil, nil)
      
        accumulatedCookies = UTIL:parseCookies(header["set-cookie"] or "")
        
        if (status == 302) then
          local redirectTo = header["location"]
          
          if (string.find(redirectTo, "?error") ~= nil) then
            local msg = "Bad login url."
            log(logPrefix..msg, LOGLEVELS.ERROR)
            return false, msg
          end
          
          challengeUrl = UTIL:startsWith(redirectTo, "/") and BASE_URL..redirectTo or redirectTo
        end
      end
      
      if (response ~= 1 or status ~= 200) then
        return false, "Could not find login page."
      end
      
      debug(logPrefix.."Login page found, submitting credentials.")
      
      --Hack up the HTML and find the form action, verification token and return url.
      local action = BASE_URL..UTIL:cutString(contentStr,"<form action=\"","\"") 
            
      local loginParams = {
        ["ReturnUrl"] = UTIL:cutString(action, "returnUrl=", nil),
        ["Email"] = userName,
        ["Password"] = password,
        ["__RequestVerificationToken"] = UTIL:cutString(contentStr, "__RequestVerificationToken\" type=\"hidden\" value=\"", "\"") 
      }
      
      local loginBody = UTIL:buildKeyValueString(loginParams)
      
      local HEADERS = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
          ["Cookie"] = accumulatedCookies,
          ["Content-Length"] = #loginBody
        }
            
      response, status, header, contentStr = UTIL:request(challengeUrl, "POST", HEADERS, loginBody)
          
      accumulatedCookies = UTIL:parseCookies(header["set-cookie"])
      
      if (response ~= 1 or status ~= 302) then
        log(logPrefix.."Login failed.  Response status is: "..status, LOGLEVELS.ERROR)
        return false, "Login failed"
      end
      
      debug(logPrefix.."Login successful, following callback url.")
      local loginRedirect = BASE_URL..header["location"]
        
      HEADERS = {
        ["Cookie"] = accumulatedCookies
      }
        
        --Follow the redirect to the callback url.
      response, status, header, contentStr = UTIL:request(loginRedirect, "GET", HEADERS, nil)
        
      if (response ~= 1 or status ~= 302) then
        log(logPrefix.."Failure navigating to callback url.", LOGLEVELS.ERROR)
        return false, "Could not execute login callback."
      end
        
      loginRedirect = header["location"]
      local code = UTIL:cutString(loginRedirect,"code=","&")
      local scope = UTIL:urldecode(UTIL:cutString(loginRedirect,"scope=","&"))
         
      debug(logPrefix.."Got login code, beginning token retrieval.  Last step....whew!")
      
      local qry = {
        ["client_id"] = self.API_CONFIG.CLIENTID,
        ["client_secret"] = UTIL:base64encode(self.API_CONFIG.CLIENT_SECRET),
        ["code"] = code,
        ["code_verifier"] = codeVerifier,
        ["grant_type"] = "authorization_code",
        ["redirect_uri"] = UTIL:split(loginRedirect,"?")[1],
        ["scope"] = scope
      }
          
      local tokenPayload = UTIL:buildKeyValueString(qry)
      
      HEADERS = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Content-Length"] = #tokenPayload
      }
    
      response, status, header, contentStr = UTIL:request(self.API_CONFIG.TOKEN_URL, "POST", HEADERS, tokenPayload)
      
      if (response ~= 1 or status ~= 200) then
        local msg = "Failed to retrieve access token."
        log(logPrefix, msg, LOGLEVELS.ERROR)
        return false, msg
      end
      
      local token = json.decode(contentStr).access_token
      debug(logPrefix.."Successfully cut access token.")
      
      HEADERS = {
        ["Authorization"] = "Bearer "..token
      }
      
      response, status, header, contentStr = UTIL:request(self.API_CONFIG.ACCOUNT_URL, "GET", HEADERS)
      
      if (response ~= 1 or status ~= 200) then
        local msg = "Failed getting account info"
        log(logPrefix..msg, LOGLEVELS.ERROR)
        return false, msg
      end
      
      --Let's not make it difficult just yet.  Assume only 1 account.
      local accountId = json.decode(contentStr).accounts[1].id
      
      debug(logPrefix.."Found account id "..accountId)
        
      return true, token, accountId
      
    end,
    
    changeDeviceStatus = function(self, token, accountId, serialNumber, deviceId, gatewayDeviceId, deviceFamily, action)
      local logPrefix = "("..self.API_CONFIG.NAME.."::changeDeviceStatus): "
      debug(logPrefix.."Requesting action "..(action or "NIL").." on device "..(serialNumber or "NIL").." of type "..deviceFamily)
      
      local resultText -- Summary of the result

      local response, status, header, contentStr
      
      if (action ~= "0" and action ~= "1") then
        log(logPrefix.."Unknown device state requested: "..(action or "NIL").." for device "..(serialNumber or "NIL").."... Aborting state change.", LOGLEVELS.WARN)
        return false, "Unknown device state request"
      end
      
      local HEADERS = {
        ["Authorization"] = "Bearer "..token,
        ["Content-Length"] = 0
      }
      
      local actionText, messageText, url
            
      if (deviceFamily == "lamp") then
        actionText = action == "1" and "on" or "off"
        messageText = "Turning "..actionText
        url = self.API_CONFIG.LAMP_ACTION_URL
      elseif (deviceFamily == "garagedoor") then
        actionText = action == "1" and "open" or "close"
        messageText = action == "1" and "Opening" or "Closing"
        url = self.API_CONFIG.GDO_ACTION_URL
      else
        return false, "Unknown device family."
      end
      
      url = string.format(url, accountId, serialNumber, actionText)
      log(logPrefix..url, LOGLEVELS.ERROR)
      response, status, header, contentStr = UTIL:request(url, "PUT", HEADERS) 
        
      local result = response == 1
      
      if (result == true) then
          result = status == 202
          if (result == true) then
              resultText = "Successfully changed status to " .. action
              local refreshAfterChangeInterval = (luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_AFTER_CHANGE_INTERVAL, gatewayDeviceId) or PLUGIN_CONFIG.REFRESH_AFTER_CHANGE)
              debug(logPrefix.."State change command issued.  Will refresh status in "..refreshAfterChangeInterval.." seconds.")
              luup.call_delay('refreshDevices', refreshAfterChangeInterval, "")
              luup.device_message(deviceId, 4, messageText, PLUGIN_CONFIG.REFRESH_AFTER_CHANGE_INTERVAL, PLUGIN_CONFIG.NAME)
          else
              resultText = "State change error.  Response status from myQ is: "..status
              log(logPrefix..resultText,LOGLEVELS.ERROR)
              luup.device_message(deviceId, 2, "Failed "..messageText, PLUGIN_CONFIG.REFRESH_AFTER_CHANGE_INTERVAL, PLUGIN_CONFIG.NAME)
          end
      else
          resultText = "Unsuccessful at communicating with the myQ service"
          log(logPrefix..resultText,LOGLEVELS.ERROR)
      end
      
      
      return result, resultText
    end,
    
    inspectDevices = function(self, securityToken, accountId, gatewayDeviceId)
      local logPrefix = "("..self.API_CONFIG.NAME.."::inspectDevices): "

      -- Statuses for doors
      local doorStatuses = {
        ["closed"] = "0",
        ["open"] = "1",
        ["stopped"] = "3",
        ["opening"] = "4",
        ["closing"] = "5",
        ["faulted"] = "7", -- faulted
        ["autoreverse"] = "7", -- faulted
        ["unknown"] = "10" -- offline
      }

      local connectionResult -- True if successful, false if not
      local connectionText -- Holds issue with connection
      local openerInfo = {} -- Table to hold info about openers
      local ParentName = nil
      local ParentId = nil
      local numGDO = 0
      local numLights= 0
      local response, status, header, contentStr
             
      local HEADERS = {
        ["Authorization"] = "Bearer "..securityToken
      }
      response, status, header, contentStr = UTIL:request(string.format(self.API_CONFIG.DEVICES_URL, accountId), "GET", HEADERS)
        
      -- Check out our response
      if (response == 1 and status == 200) then
        --json parser is dumb and can't handle empty arrays.
        local responseStr = contentStr:gsub('%[%]',"null")
        local deviceContent = json.decode(responseStr)

       
        debug(logPrefix.."Parsing devices.")
        connectionResult = true
        local numOpeners = 0
        -- Time to loop over our device collection
        for _, dx in ipairs(deviceContent.items) do
          
          local d = dx
          local deviceId = d.serial_number
          
          -- This is only going to return a single "Place" / gateway. fix at some point to handle multiple gateways.
          if (d.device_family == "gateway") then
            ParentName = d.name
            ParentId = d.serial_number
          elseif (d.device_family == "garagedoor") or (d.device_family == "lamp") then 
            numOpeners = numOpeners + 1
            local deviceStateValue = d.state.door_state or d.state.light_state
            local openerName = d.name
            local deviceState = doorStatuses[deviceStateValue]
                        
            -- Keep track of all the openers along with their state
            table.insert(openerInfo, numOpeners, {
              DeviceId = deviceId,
              DeviceName = d.name,
              DeviceState = deviceState, 
              DeviceStateTransitioning = (deviceState == doorStatuses["opening"] or deviceState == doorStatuses["closing"]),
              OpenerName = openerName,
              DeviceFamily = d.device_family
            })
          
            numGDO = numGDO + (d.device_family == "garagedoor" and  1 or 0)
            numLights = numLights + (d.device_family == "lamp" and 1 or 0)
            
            debug(logPrefix.."Discovered "..d.device_family.." ["..d.name.."] in state "..deviceStateValue)
          else
            -- don't recognize this device.
            log(logPrefix.."Unknown Device Type Encountered.  Device Family: " .. (d.device_family or "NIL"),LOGLEVELS.WARN)
          end
        end
        
      else
        connectionResult = false
        connectionText = "Unsuccessful at connecting with device URL!"
        log(logPrefix.."Unsuccessful at connecting with device URL!",LOGLEVELS.ERROR)
      end
    
      if connectionResult == true then
        luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.NUM_DOORS, tostring(numGDO), gatewayDeviceId)
        luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.NUM_LIGHTS, tostring(numLights), gatewayDeviceId)
        debug("("..self.API_CONFIG.NAME.."::inspectDevices): Retrieved device data")
      else
        luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.NUM_DOORS, "ERROR: Could not initialize connection.", gatewayDeviceId)
        luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.NUM_LIGHTS, "        Check username and password.", gatewayDeviceId)	
        log("("..self.API_CONFIG.NAME.."::inspectDevices): FAILED to Retreived device data",LOGLEVELS.ERROR)
      end
      return connectionResult, openerInfo, ParentId, ParentName
    end
    
  } --end myQ API
  
end

local function refreshToken(logPrefix)

  if (os.difftime(os.time(),PLUGIN_CONFIG.LAST_TOKEN_REFRESH) > PLUGIN_CONFIG.MAX_TOKEN_AGE) then
    local result, tokenOrMsg, accountId = MYQ_API:login(PLUGIN_CONFIG.USERNAME, PLUGIN_CONFIG.PASSWORD)
    
    if (result == false) then
      local msg1 = "myQ Authorization Failed."
      local msg2 = "Check settings in myQ setup."
      
      luup.variable_set (MYQGATEWAY_SID,PLUGIN_VARS.NUM_DOORS,msg1,MyQGatewayID)
      luup.variable_set (MYQGATEWAY_SID,PLUGIN_VARS.NUM_LIGHTS,msg2,MyQGatewayID)
      task(msg1.." "..msg2, TASK_ERROR_PERM)
      
      log(logPrefix..msg1..": "..(tokenOrMsg or "No Text"), LOGLEVELS.ERROR)
      return false
    end
    
    PLUGIN_CONFIG.SECURITY_TOKEN = tokenOrMsg
    PLUGIN_CONFIG.ACCOUNTID = accountId
    PLUGIN_CONFIG.LAST_TOKEN_REFRESH = os.time()
    debug(logPrefix.."TOKEN RETRIEVAL SUCCESSFUL!!")
    luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.TOKEN_TIMESTAMP, UTIL:getFriendlyTimestamp(PLUGIN_CONFIG.LAST_TOKEN_REFRESH), MyQGatewayID)
    clearTask()
  else
    debug(logPrefix.."Token assumed valid: "..(os.difftime(os.time(), PLUGIN_CONFIG.LAST_TOKEN_REFRESH) / 60).." minutes old.")
  end
  
  debug(logPrefix.."Bearer "..PLUGIN_CONFIG.SECURITY_TOKEN)
end


function refreshDevices()
  local logPrefix = "("..PLUGIN_CONFIG.NAME.."::refreshDevices): "
  debug(logPrefix.."Starting status poll process.")
  
  local tokenResult = refreshToken(logPrefix)
  
  if (tokenResult == false) then
    return
  end
  
  local devicesStillTransitioning = false
        
  local connectionResult, openerInfo, _, _ = MYQ_API:inspectDevices(PLUGIN_CONFIG.SECURITY_TOKEN, PLUGIN_CONFIG.ACCOUNTID)

  if (connectionResult == false) then
    log(logPrefix.."Error on refresh doors, Exiting.",LOGLEVELS.ERROR)
    return
  end
  
  for i = 1, #openerInfo do
    local deviceId = openerInfo[i].DeviceId
    local childId = child_id_lookup_table[deviceId]
    debug(logPrefix.."Processing myQ device ["..(deviceId or "NIL").."] vera id ["..(childId or "NIL").."].")
    
    if openerInfo[i].DeviceFamily == "garagedoor" then
      
      luup.set_failure(0,childId)
      
      local deviceStatusValue = openerInfo[i].DeviceState
      local lastStatusText = luup.variable_get(GDO_SID, PLUGIN_VARS.STATUS,  childId)
      if (deviceStatusValue ~= lastStatusText) then
        luup.variable_set("urn:micasaverde-com:SecuritySensor1", PLUGIN_VARS.LAST_TRIP, os.time(), childId)
      end
      
      if (not openerInfo[i].DeviceStateTransitioning) then
        --remove any messages on the device.
        luup.device_message(deviceId, 22, "Completed", 0, PLUGIN_CONFIG.NAME)
      end
      
      devicesStillTransitioning = devicesStillTransitioning or openerInfo[i].DeviceStateTransitioning
      
      luup.variable_set(GDO_SID, PLUGIN_VARS.STATUS, deviceStatusValue, childId)
      
    else
      log(logPrefix..openerInfo[i].DeviceFamily.." devices not currently supported.",LOGLEVELS.WARN)						
    end
  end
  
  --Use the LastCheck variable to store the last time the doors were checked
  --The timestamp is set for when the last re-auth occurred
  luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.LAST_CHECK, UTIL:getFriendlyTimestamp(os.time()), MyQGatewayID)
  
  if (devicesStillTransitioning) then
    -- one or more devices are transitioning - queue a recheck
    luup.call_delay('refreshDevices', 5, "")
  end
  
  debug(logPrefix.."Poll process completed.")
end


function init(lul_device)
	if (MyQGatewayID == nil) then MyQGatewayID = lul_device end -- save the global device ID
	local isDisabled = luup.attr_get("disabled", lul_device)
  local logPrefix = "("..PLUGIN_CONFIG.NAME.."::init): "
	if ((isDisabled == 1) or (isDisabled == "1")) then
		log(logPrefix.."MyQ Gateway Plugin "..VERSION.." - ************** DISABLED **************", LOGLEVELS.WARN)
		PLUGIN_CONFIG.PLUGIN_DISABLED = true
		-- mark device as disabled
		return true, "Plugin Disabled.", "MyQGateway"
	end
	debug(logPrefix.."MyQ Gateway Plugin "..VERSION.." DeviceId " ..lul_device.." - ************** STARTING **************")
	-- Not sure why, but the task (status) seems to only work as expected when the function is called via timer.
	-- This allows a status message to appear for the device to allow the user to change settings, while at the same time
	-- does not "fail" the initiation.  this allows the user to make use of the UI to set the initial parameters
	-- instead of going to advanced tab and manually enter values which could be problematic for some.
	
	luup.variable_set (MYQGATEWAY_SID,"PLUGIN_VERSION",VERSION,MyQGatewayID)

	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.USERNAME, "", MyQGatewayID)
	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.PASSWORD, "", MyQGatewayID)
	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_INTERVAL, PLUGIN_CONFIG.REFRESH_INTERVAL, MyQGatewayID)
	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_AFTER_CHANGE_INTERVAL, PLUGIN_CONFIG.REFRESH_AFTER_CHANGE, MyQGatewayID)
	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.DEBUG_MODE, (PLUGIN_CONFIG.DEBUG_MODE and "1" or "0"), MyQGatewayID)
	UTIL:initVar(MYQGATEWAY_SID, PLUGIN_VARS.DEBUG_MODE_TEXT, "DISABLED", MyQGatewayID)

	luup.set_failure(0)

	-- load the PLUGIN_CONFIG variables before the deferred startup code runs
	PLUGIN_CONFIG.DEBUG_MODE = (tonumber(luup.variable_get(MYQGATEWAY_SID, "DEBUG_MODE", MyQGatewayID),10) == 1) and true or (PLUGIN_CONFIG.FORCE_DEBUG or false)
	debug(logPrefix.."MyQ Gateway Plugin Options - DEBUG_MODE ["..(PLUGIN_CONFIG.DEBUG_MODE and "ENABLED" or "DISABLED").."]")
	luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.DEBUG_MODE_TEXT, (PLUGIN_CONFIG.DEBUG_MODE and "ENABLED" or "DISABLED"), lul_device)

	luup.call_timer("startupDeferred", 1, "1", "")
	return true, "Plugin starting.", "MyQGateway"
end


function startupDeferred()

	local foundIssue = false --Any problem with username/password?
	local issueMessage = "ERROR: " --Our fancy error message
  local logPrefix = "("..PLUGIN_CONFIG.NAME.."::startupDeferred): "

	-- Grab our username and password from advanced
	-- Throw an error if any or both are not set below
	PLUGIN_CONFIG.USERNAME = luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.USERNAME, MyQGatewayID) or PLUGIN_CONFIG.USERNAME
  
	if (PLUGIN_CONFIG.USERNAME == nil or PLUGIN_CONFIG.USERNAME == "") then
		luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.USERNAME, "", MyQGatewayID)
		foundIssue = true
		issueMessage = "Username not configured. "
		debug(logPrefix.."MyQ Username not specified.")
	end

	PLUGIN_CONFIG.PASSWORD = luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.PASSWORD, MyQGatewayID) or PLUGIN_CONFIG.PASSWORD
	if (PLUGIN_CONFIG.PASSWORD == nil or PLUGIN_CONFIG.PASSWORD == "") then
		luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.PASSWORD, "", MyQGatewayID)
		foundIssue = true
		issueMessage = issueMessage .. "Password not configured."
		debug(logPrefix.."MyQ Password not specified.")
	end

	local refreshInterval = luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_INTERVAL, MyQGatewayID)
	if (refreshInterval ~= nil and tonumber(refreshInterval) > 0) then
		debug(logPrefix.."Status refresh on your opener(s) will be called every:" .. refreshInterval)
	else
		debug(logPrefix.."Setting refresh interval to 120 sec by default")
		luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_INTERVAL, 120, MyQGatewayID)
	end

	local refreshAfterChangeInterval = luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_AFTER_CHANGE_INTERVAL, MyQGatewayID)
	if (refreshAfterChangeInterval == nil) then
		luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_AFTER_CHANGE_INTERVAL, PLUGIN_CONFIG.REFRESH_AFTER_CHANGE, MyQGatewayID)
	end

	if (foundIssue == true) then
		local msg = issueMessage .. "  Check settings in myQ setup."
		task(msg, TASK_ERROR_PERM)
		luup.variable_set (MYQGATEWAY_SID,PLUGIN_VARS.NUM_DOORS,issueMessage,MyQGatewayID)
		luup.variable_set (MYQGATEWAY_SID,PLUGIN_VARS.NUM_LIGHTS,"",MyQGatewayID)
		debug(logPrefix.."MyQ Gateway Plugin "..VERSION.." - ********** STARTUP COMPLETE **********")
		return
	end
  
  debug(logPrefix.."ATTEMPTING INITIAL API LOGIN")
	
  local tokenResult = refreshToken(logPrefix)
  
  if (tokenResult == false) then
    return
  end
  
	local connectionResult, openerInfo, _, _ = MYQ_API:inspectDevices(PLUGIN_CONFIG.SECURITY_TOKEN, PLUGIN_CONFIG.ACCOUNTID, MyQGatewayID)
	
  if (connectionResult == false) then
		log(logPrefix.."No data retrieved.",LOGLEVELS.ERROR)
		log(logPrefix.."Unable to continue. Exiting.",LOGLEVELS.ERROR)
		debug(logPrefix.."MyQ Gateway Plugin "..VERSION.." - ********** STARTUP COMPLETE **********")
		return
	end

	debug(logPrefix.."Processing child devices.")
	local child_devices = luup.chdev.start(MyQGatewayID); -- create child devices

	debug(logPrefix.."Number of devices to process = ["..(#openerInfo or "NIL").."].")
	
	for i = 1, #openerInfo do -- Over the individual openers we go
		debug(logPrefix.."Processing device ["..(i or "NIL").."] name ["..(openerInfo[i].OpenerName or "NIL").."] ")
		if openerInfo[i].DeviceFamily == "garagedoor" then
      luup.chdev.append(MyQGatewayID, -- parent (this device)
      child_devices, -- Pointer from above start call
      openerInfo[i].DeviceId, -- the serial number will be the device id.
      openerInfo[i].OpenerName,
      GDO_DEVICE_TYPE, -- deviceType defined in device file
      "D_MyQGarageDoor1.xml", -- Device file
      "", -- No implementation file
      "", -- No parameters to set
      false) -- Not embedded child device (can go in any room)
			
		elseif openerInfo[i].DeviceFamily == "lamp" then
			luup.chdev.append(MyQGatewayID, -- parent (this device)
				child_devices, -- Pointer from above start call
				openerInfo[i].DeviceId, -- Our child ID taken from the opener device id
				openerInfo[i].OpenerName, -- Child device description
				LAMP_DEVICE_TYPE, -- deviceType defined in device file
				"D_BinaryLight1.xml", -- Device file
				"", -- No implementation file
				"", -- No parameters to set
				false) -- Not embedded child device (can go in any room)		
		end
	end
	luup.chdev.sync(MyQGatewayID, child_devices) -- any changes in configuration will cause a restart at this point
  
	for k, v in pairs(luup.devices) do
		-- if I am the parent device
		if v.device_num_parent == MyQGatewayID then
			debug(logPrefix.."child_id_lookup_table["..(v.id or "NIL").."] = "..(k or "NIL"))
			child_id_lookup_table[v.id] = k
			debug(logPrefix.."child_deviceid_lookup_table["..(k or "NIL").."] = "..(v.id or "NIL"))
			child_deviceid_lookup_table[k] = v.id
		end
	end
	
	-- Fire up our timer to check on auth code and door status
	-- periodic refresh of security token, no longer used.
	debug(logPrefix.."ID for MyQGateway is " .. (MyQGatewayID or "NIL"))
	luup.call_delay('refreshDevicesLoop', 10, "") --Wait 10 seconds to refresh devides for the first time.
  luup.set_failure(0)
	debug(logPrefix.."MyQ Gateway Plugin "..VERSION.." - ********** STARTUP COMPLETE **********")
	return true
end


function refreshDevicesLoop()
    local logPrefix = "("..PLUGIN_CONFIG.NAME.."::refreshDevicesLoop): "
    local refreshInterval = tonumber((luup.variable_get(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_INTERVAL, MyQGatewayID) or PLUGIN_CONFIG.REFRESH_INTERVAL))
    if (refreshInterval ~= nil and refreshInterval > 0) then
        if (refreshInterval < 10) then 
          refreshInterval = 10
          log(logPrefix.."Refreshing interval is too short, defaulting to minimum of "..refreshInterval.." seconds.",LOGLEVELS.WARN)
        else
          log(logPrefix.."Refreshing devices every "..refreshInterval.." seconds.",LOGLEVELS.WARN)
        end
        luup.call_delay('refreshDevicesLoop', refreshInterval, "")
    else
        log(logPrefix.."Devices will not update, configured refresh interval is invalid.",LOGLEVELS.WARN)
        luup.variable_set(MYQGATEWAY_SID, PLUGIN_VARS.REFRESH_INTERVAL, 0, MyQGatewayID)
    end
    refreshDevices()
end

