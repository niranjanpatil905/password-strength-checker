"""
Password Strength Checker - Cybersecurity Project 2026
Analyzes password strength, checks against common breaches, and provides recommendations.
"""

import re
import hashlib
import requests
import argparse
import getpass
from datetime import datetime

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = [
            '123456', 'password', '12345678', 'qwerty', '123456789',
            'letmein', '1234567', 'football', 'iloveyou', 'admin',
            'welcome', 'monkey', 'login', 'abc123', '111111',
            '123123', 'password123', '1234', 'baseball', 'qwertyuiop'
        ]
        
        self.common_patterns = [
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
            r'(.)\1{2,}',  # Repeated characters
            r'^(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        ]
        
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 32
        if re.search(r'[^\w\s]', password):
            charset_size += 10
            
        if charset_size == 0:
            return 0
            
        entropy = len(password) * (charset_size.bit_length() - 1)
        return entropy
    
    def check_breach_database(self, password):
        """Check if password exists in known breach databases using Have I Been Pwned API"""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        
        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
            if response.status_code == 200:
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except:
            return -1  # Unable to check
    
    def analyze_password(self, password):
        """Comprehensive password analysis"""
        results = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
            'has_repeated': bool(re.search(r'(.)\1{2,}', password)),
            'has_sequential': bool(re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower())),
            'is_common': password.lower() in [p.lower() for p in self.common_passwords],
            'entropy': self.calculate_entropy(password),
            'breach_count': self.check_breach_database(password)
        }
        
        # Calculate strength score
        score = 0
        feedback = []
        
        # Length scoring
        if results['length'] >= 16:
            score += 4
        elif results['length'] >= 12:
            score += 3
        elif results['length'] >= 8:
            score += 2
        else:
            score += 1
            feedback.append("Password is too short (minimum 8 characters recommended)")
        
        # Character variety scoring
        char_types = sum([results['has_lowercase'], results['has_uppercase'], 
                         results['has_digits'], results['has_special']])
        
        if char_types == 4:
            score += 4
        elif char_types == 3:
            score += 3
        elif char_types == 2:
            score += 2
            feedback.append("Add more character types (uppercase, lowercase, digits, special chars)")
        else:
            score += 1
            feedback.append("Use a mix of uppercase, lowercase, digits, and special characters")
        
        # Penalties
        if results['has_repeated']:
            score -= 2
            feedback.append("Avoid repeated characters (e.g., 'aaa', '111')")
        
        if results['has_sequential']:
            score -= 2
            feedback.append("Avoid sequential patterns (e.g., '123', 'abc')")
        
        if results['is_common']:
            score = 0
            feedback.append("This is a commonly used password - very insecure!")
        
        if results['breach_count'] > 0:
            score = max(0, score - 3)
            feedback.append(f"Password found in {results['breach_count']:,} data breaches!")
        
        # Entropy bonus
        if results['entropy'] >= 80:
            score += 2
        elif results['entropy'] >= 60:
            score += 1
        
        results['score'] = max(0, min(10, score))
        results['feedback'] = feedback
        
        # Determine strength level
        if results['score'] >= 8:
            results['strength'] = "VERY STRONG"
        elif results['score'] >= 6:
            results['strength'] = "STRONG"
        elif results['score'] >= 4:
            results['strength'] = "MODERATE"
        elif results['score'] >= 2:
            results['strength'] = "WEAK"
        else:
            results['strength'] = "VERY WEAK"
            
        return results
    
    def generate_report(self, password):
        """Generate detailed password analysis report"""
        results = self.analyze_password(password)
        
        print(f"\n{'='*70}")
        print(f"PASSWORD STRENGTH ANALYZER - Cybersecurity Project 2026")
        print(f"{'='*70}")
        print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # Masked password display
        masked = password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password)
        print(f"Password: {masked}")
        print(f"Length: {results['length']} characters")
        print(f"\n{'='*70}")
        
        # Character Analysis
        print(f"CHARACTER ANALYSIS")
        print(f"{'='*70}")
        print(f"{'Feature':<30}{'Status':<20}{'Score Impact'}")
        print(f"{'-'*70}")
        print(f"{'Lowercase Letters (a-z)':<30}{'✓ YES' if results['has_lowercase'] else '✗ NO':<20}{'+1' if results['has_lowercase'] else '0'}")
        print(f"{'Uppercase Letters (A-Z)':<30}{'✓ YES' if results['has_uppercase'] else '✗ NO':<20}{'+1' if results['has_uppercase'] else '0'}")
        print(f"{'Digits (0-9)':<30}{'✓ YES' if results['has_digits'] else '✗ NO':<20}{'+1' if results['has_digits'] else '0'}")
        print(f"{'Special Characters':<30}{'✓ YES' if results['has_special'] else '✗ NO':<20}{'+1' if results['has_special'] else '0'}")
        print(f"{'Repeated Characters':<30}{'✗ DETECTED' if results['has_repeated'] else '✓ NONE':<20}{'-2' if results['has_repeated'] else '0'}")
        print(f"{'Sequential Patterns':<30}{'✗ DETECTED' if results['has_sequential'] else '✓ NONE':<20}{'-2' if results['has_sequential'] else '0'}")
        print(f"{'Common Password':<30}{'✗ YES' if results['is_common'] else '✓ NO':<20}{'CRITICAL' if results['is_common'] else '0'}")
        
        print(f"\n{'='*70}")
        print(f"SECURITY METRICS")
        print(f"{'='*70}")
        print(f"Entropy: {results['entropy']:.2f} bits")
        print(f"Character Sets Used: {sum([results['has_lowercase'], results['has_uppercase'], results['has_digits'], results['has_special']])}/4")
        
        if results['breach_count'] > 0:
            print(f"Data Breach Exposure: {results['breach_count']:,} occurrences found!")
        elif results['breach_count'] == 0:
            print(f"Data Breach Exposure: ✓ Not found in known breaches")
        else:
            print(f"Data Breach Exposure: Unable to check (API unavailable)")
        
        print(f"\n{'='*70}")
        print(f"STRENGTH ASSESSMENT")
        print(f"{'='*70}")
        
        # Visual strength meter
        score = results['score']
        meter = '[' + '█' * score + '░' * (10 - score) + ']'
        print(f"\nScore: {score}/10 {meter}")
        print(f"\nStrength Level: {results['strength']}")
        
        # Color-coded strength
        if results['strength'] == "VERY STRONG":
            print("Status: ✓✓✓ Excellent password security!")
        elif results['strength'] == "STRONG":
            print("Status: ✓✓ Good password security")
        elif results['strength'] == "MODERATE":
            print("Status: ✓ Acceptable but could be improved")
        elif results['strength'] == "WEAK":
            print("Status: ⚠ Vulnerable to attacks")
        else:
            print("Status: ✗✗✗ CRITICAL - Change immediately!")
        
        print(f"\n{'='*70}")
        print(f"RECOMMENDATIONS")
        print(f"{'='*70}")
        
        if results['feedback']:
            for i, rec in enumerate(results['feedback'], 1):
                print(f"{i}. {rec}")
        else:
            print("✓ No recommendations - your password is excellent!")
        
        # Time to crack estimation (simplified)
        print(f"\n{'='*70}")
        print(f"CRACK TIME ESTIMATE")
        print(f"{'='*70}")
        
        combinations = 95 ** results['length']  # Approximate
        guesses_per_second = 10**9  # Modern GPU cracking speed
        
        if results['is_common']:
            print("Time to crack: INSTANT (common password)")
        elif results['entropy'] < 40:
            seconds = combinations / guesses_per_second
            if seconds < 60:
                print(f"Time to crack: {seconds:.2f} seconds")
            elif seconds < 3600:
                print(f"Time to crack: {seconds/60:.2f} minutes")
            else:
                print(f"Time to crack: {seconds/3600:.2f} hours")
        elif results['entropy'] < 60:
            days = (combinations / guesses_per_second) / 86400
            print(f"Time to crack: {days:.1f} days")
        elif results['entropy'] < 80:
            years = (combinations / guesses_per_second) / (86400 * 365)
            print(f"Time to crack: {years:.1f} years")
        else:
            centuries = (combinations / guesses_per_second) / (86400 * 365 * 100)
            print(f"Time to crack: {centuries:.1f} centuries")
        
        print(f"\n{'='*70}\n")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Password Strength Checker - Cybersecurity Project 2026')
    parser.add_argument('-p', '--password', help='Password to analyze (will prompt if not provided)')
    parser.add_argument('--show', action='store_true', help='Show password in output (use with caution)')
    
    args = parser.parse_args()
    
    checker = PasswordStrengthChecker()
    