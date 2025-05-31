import requests
import pandas as pd
from datetime import datetime, timedelta
import json
from termcolor import colored
import textwrap

def fetch_security_advisories():
    """
    GitHub Security Advisory Database에서 최신 보안 취약점 정보를 가져옵니다.
    """
    url = "https://api.github.com/advisories"
    
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Python-Security-Scanner'
    }
    
    params = {
        'per_page': 20,
        'sort': 'updated',
        'direction': 'desc'
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        advisories = response.json()
        vulnerabilities = []
        
        for advisory in advisories:
            cvss = advisory.get('cvss', {})
            cvss_score = cvss.get('score', 'N/A') if cvss else 'N/A'
            cvss_vector = cvss.get('vector_string', 'N/A') if cvss else 'N/A'
            
            affected_packages = []
            for vuln in advisory.get('vulnerabilities', []):
                package = vuln.get('package', {})
                if package:
                    affected_packages.append(f"{package.get('ecosystem', '')}: {package.get('name', '')}")
            
            vulnerabilities.append({
                'id': advisory['ghsa_id'],
                'summary': advisory['summary'],
                'description': advisory['description'],
                'severity': advisory.get('severity', 'N/A'),
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'affected_packages': '; '.join(affected_packages) if affected_packages else 'N/A',
                'published_date': advisory['published_at'],
                'updated_date': advisory['updated_at'],
                'references': '; '.join(advisory.get('references', [])) if advisory.get('references') else 'N/A'
            })
        
        # DataFrame으로 변환
        df = pd.DataFrame(vulnerabilities)
        
        # CSV 파일로 저장
        current_date = datetime.now().strftime('%Y%m%d')
        filename = f'github_security_advisories_{current_date}.csv'
        df.to_csv(filename, index=False, encoding='utf-8')
        
        print(f"\n✅ {len(vulnerabilities)}개의 보안 취약점 정보를 {filename}에 저장했습니다.")
        return df
        
    except requests.RequestException as e:
        print(f"❌ 보안 취약점 정보 가져오기 실패: {e}")
        return None

def get_severity_color(severity):
    """심각도에 따른 색상을 반환합니다."""
    colors = {
        'critical': 'red',
        'high': 'yellow',
        'medium': 'cyan',
        'low': 'green',
        'N/A': 'white'
    }
    return colors.get(severity.lower(), 'white')

def print_advisory(idx, advisory, show_details=False):
    """
    보안 권고사항을 보기 좋게 출력하는 함수
    """
    severity = advisory['severity'].lower()
    severity_color = get_severity_color(severity)
    
    # 기본 정보 출력
    print(f"\n{colored('━', 'white') * 100}")
    print(f"#{idx + 1} {colored(advisory['id'], 'blue')} - {colored(severity.upper(), severity_color)}")
    print(f"{colored('━', 'white') * 100}")
    
    # 요약 정보
    print(f"📝 {colored('요약', 'yellow')}: {advisory['summary']}")
    print(f"🎯 {colored('영향받는 패키지', 'yellow')}: {advisory['affected_packages']}")
    if advisory['cvss_score'] != 'N/A':
        print(f"⚠️  {colored('CVSS 점수', 'yellow')}: {advisory['cvss_score']}")
    
    # 상세 정보 표시 여부
    if show_details:
        print(f"\n📋 {colored('상세 설명', 'yellow')}:")
        description = textwrap.fill(advisory['description'], width=95, initial_indent='  ', subsequent_indent='  ')
        print(description)
        
        if advisory['references'] != 'N/A':
            print(f"\n🔗 {colored('참조 링크', 'yellow')}:")
            for ref in advisory['references'].split('; '):
                print(f"  • {ref}")
    else:
        print(f"\n💡 자세한 내용을 보려면 'D'를 입력하세요.")
    
    print(f"{colored('━', 'white') * 100}")

if __name__ == "__main__":
    print("\n🔍 GitHub Security Advisory Database에서 최신 보안 취약점 정보를 가져오는 중...\n")
    advisories_df = fetch_security_advisories()
    
    if advisories_df is not None:
        print("\n📋 최신 보안 취약점 목록:")
        
        idx = 0
        while idx < len(advisories_df):
            advisory = advisories_df.iloc[idx]
            print_advisory(idx, advisory)
            
            # 사용자 입력 처리
            user_input = input("\n다음(N) / 이전(P) / 상세보기(D) / 종료(Q): ").upper()
            
            if user_input == 'N':
                idx = min(idx + 1, len(advisories_df) - 1)
            elif user_input == 'P':
                idx = max(0, idx - 1)
            elif user_input == 'D':
                print("\n" + "=" * 100)
                print_advisory(idx, advisory, show_details=True)
                input("\n계속하려면 Enter를 누르세요...")
            elif user_input == 'Q':
                break 