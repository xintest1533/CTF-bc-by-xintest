import requests
import json
import sys

def submit_flag(attacker_id, target_id, flag, judge_url="http://127.0.0.1:8080"):
    url = f"{judge_url}/submit_flag"
    
    payload = {
        "attacker_id": attacker_id,
        "target_id": target_id,
        "flag": flag
    }
    
    try:
        response = requests.post(url, json=payload)
        result = response.json()
        print(f"提交结果: {result}")
        return result
    except Exception as e:
        print(f"提交失败: {str(e)}")
        return {"success": False, "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("用法: python submit_flag.py <attacker_id> <target_id> <flag> [judge_url]")
        print("示例: python submit_flag.py player1 player2 FLAG{abc123}")
        sys.exit(1)
    
    attacker_id = sys.argv[1]
    target_id = sys.argv[2]
    flag = sys.argv[3]
    judge_url = sys.argv[4] if len(sys.argv) > 4 else "http://127.0.0.1:8080"
    
    submit_flag(attacker_id, target_id, flag, judge_url)
