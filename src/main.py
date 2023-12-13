import base64
from random import randrange
from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/v1/map", response_class=JSONResponse)
def threat_map(request: Request):
    creds = request.headers.get("authorization")
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    try:
        username, password = base64.b64decode(creds.replace("Basic", "").strip()).decode("utf-8").split(":")
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    if username != "jose" and password != "0ed77b11f050123501f35863":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    lst = [
    "RU","TF","DK","SV","SN","CZ","SI","KR","JP","BS","VE","TL","UZ","AU","CL","QA","BM","MZ","EE","AT","GE","TD","LI","CI","VN","KW","AR","NI","MG","BR","RW","TJ","NA","PL","LR","VU","BZ","YT","LA","MC","MT","BY","GI","EG","LK","SA","DE","TT","SK","SS","LT","JM","MU","SR","CY","PF","BB","SZ","AG","HU","FI","ST","RS","EC","TM","AO","KG","MR","TG","IE","JE","RE","DJ","BQ","BD","SX","UA","DO","ES","NO","BA","TH","TN","BH","PS","TR","CU","MA","AL","SY","CO","BE","DZ","PM","GF","AX","AZ","GL","GT","MM","PE","PY","CK","SG","US","KE","LY","YE","UG","NZ","KZ","SL","UY","HN","GU","AE","IQ","IR","DM","NL","IN","CN","GQ","NE","BN","ME","GM","LS","ZM","ET","CD","SD","TC","MY","XK","HK","KM","MV","NP","MQ","VG","BW","MP","SE","GH","KN","BF","CH","BT","SC","AW","VI","PW","PK","TW","BO","LU","CA","ML",
    "PR","FR","KY","FJ","LV","PG","MX","GG","RO","CW","TZ","BI","SO","MO","PH","ZW","ER","NC","LC","CG","FO","GA","IM","ID","GY","OM","MN","WS","AM","KI","AF","PA","LB","HT","MD","AD","ZA","GN","PT","TO","NG","IL","JO","BG","IT","GB","IS","GP","CR","HR","MK","KH","GR","GD","MW","BJ","CM","CV"]

    data = {}
    for item in lst:
        data[item] = randrange(0, 10000)

    sum_ips = sum(data.values())
    data["top5"] = {key: val for key,val in sorted(data.items(), key=lambda item: item[1])[-5:]}
    data["sum"] = sum_ips
    return data
