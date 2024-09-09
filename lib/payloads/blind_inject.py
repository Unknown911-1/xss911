import json
import os


blind_json = "lib/payloads/blind.json"


def blind_url_injection(url):
  if url.endswith('.js') or url.endswith('='):
      if os.path.exists(blind_json):
          with open(blind_json, 'r+') as f:
              data = json.load(f)
              updated = False
              for item in data['payloads']:
                  payload = item['payload']
                  if url in payload:
                      return True
                  if 'fetch(' in payload:
                      payload_url = payload.split('fetch(')[1].split(')')[0]
                      payload = payload.replace(url, payload_url)
                      item['payload'] = payload
                      updated = True
              if updated:
                  f.seek(0)
                  json.dump(data, f, indent=2)
  else:
      return False
  return False
