import streamlit as st
import re
import math
from typing import Dict, Tuple, List

class PasswordAnalyzer:
    """Enhanced password analyzer with comprehensive strength checking."""
    
    def __init__(self):
        self.character_sets = {
            'lowercase': {'pattern': r'[a-z]', 'size': 26, 'name': 'Lowercase letters'},
            'uppercase': {'pattern': r'[A-Z]', 'size': 26, 'name': 'Uppercase letters'},
            'digits': {'pattern': r'[0-9]', 'size': 10, 'name': 'Numbers'},
            'special': {'pattern': r'[^a-zA-Z0-9\s]', 'size': 32, 'name': 'Special characters'}
        }
        
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwerty|asdf|zxcv|password|admin|login|welcome)',  # Common keyboard patterns and words
        ]
        
        self.strength_thresholds = {
            'very_weak': 35,
            'weak': 59,
            'moderate': 79,
            'strong': 119,
            'very_strong': 120
        }

    def analyze_character_composition(self, password: str) -> Dict:
        """Analyze which character types are present in the password."""
        composition = {}
        total_charset_size = 0
        missing_types = []
        
        for char_type, info in self.character_sets.items():
            present = bool(re.search(info['pattern'], password))
            composition[char_type] = present
            if present:
                total_charset_size += info['size']
            else:
                missing_types.append(info['name'])
        
        return {
            'composition': composition,
            'charset_size': total_charset_size,
            'missing_types': missing_types
        }

    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy based on character set and length."""
        if not password:
            return 0
        
        analysis = self.analyze_character_composition(password)
        charset_size = analysis['charset_size']
        
        if charset_size == 0:
            charset_size = 1  # Prevent log(0)
        
        entropy = len(password) * math.log2(math.pow(charset_size,len(password)))
        return entropy

    def check_common_patterns(self, password: str) -> List[str]:
        """Check for common weak patterns in password."""
        found_patterns = []
        
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                if 'repeated' in pattern or r'(.)\1{2,}' == pattern:
                    found_patterns.append("Contains repeated characters")
                elif any(seq in pattern for seq in ['012', '123', 'abc']):
                    found_patterns.append("Contains sequential characters")
                else:
                    found_patterns.append("Contains common patterns or words")
        
        return found_patterns

    def get_strength_category(self, entropy: float) -> Tuple[str, str, str]:
        """Determine password strength category based on entropy."""
        if entropy <= self.strength_thresholds['very_weak']:
            return "Very Weak", "🔴", "danger"
        elif entropy <= self.strength_thresholds['weak']:
            return "Weak", "🟠", "warning"
        elif entropy <= self.strength_thresholds['moderate']:
            return "Moderate", "🟡", "info"
        elif entropy <= self.strength_thresholds['strong']:
            return "Strong", "🟢", "success"
        else:
            return "Very Strong", "🔵", "success"

    def estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password assuming 1 billion guesses per second."""
        if entropy <= 0:
            return "Instantly"
        
        combinations = 2 ** entropy
        # Assuming 10^9 guesses per second (modern hardware)
        seconds = combinations / (2 * 10**9)  # Divide by 2 for average case
        
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        else:
            return "More than 1000 years"

    def generate_suggestions(self, password: str) -> List[str]:
        """Generate specific suggestions to improve password strength."""
        suggestions = []
        analysis = self.analyze_character_composition(password)
        
        # Length suggestions
        if len(password) < 8:
            suggestions.append("🔸 Use at least 8 characters (12+ recommended)")
        elif len(password) < 12:
            suggestions.append("🔸 Consider using 12+ characters for better security")
        
        # Character type suggestions
        for missing_type in analysis['missing_types']:
            suggestions.append(f"🔸 Add {missing_type.lower()}")
        
        # Pattern warnings
        patterns = self.check_common_patterns(password)
        for pattern in patterns:
            suggestions.append(f"🔸 Avoid: {pattern}")
        
        # General suggestions
        if not suggestions:
            suggestions.extend([
                "✅ Your password has good character diversity!",
                "💡 Consider using a passphrase with random words",
                "💡 Enable two-factor authentication when possible"
            ])
        
        return suggestions


def main():
    st.set_page_config(
        page_title="Password Strength Analyzer",
        page_icon="🔐",
        layout="wide"
    )
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .metric-container {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .strength-meter {
        height: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🔐 Advanced Password Strength Analyzer")
    st.markdown("---")
    
    # Initialize analyzer
    analyzer = PasswordAnalyzer()
    
    # Input section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        password = st.text_input(
            "Enter your password:",
            type="password",
            help="Your password is not stored or transmitted anywhere"
        )
        
        show_password = st.checkbox("Show password")
        if show_password and password:
            st.code(password)
    
    with col2:
        st.markdown("### Quick Tips")
        st.markdown("""
        - **Length**: At least 12 characters
        - **Variety**: Mix of upper, lower, numbers, symbols
        - **Uniqueness**: Avoid common patterns
        - **Randomness**: Use a password manager
        """)
    
    # Analysis section
    if password:
        st.markdown("---")
        
        # Calculate metrics
        entropy = analyzer.calculate_entropy(password)
        strength, emoji, alert_type = analyzer.get_strength_category(entropy)
        crack_time = analyzer.estimate_crack_time(entropy)
        analysis = analyzer.analyze_character_composition(password)
        suggestions = analyzer.generate_suggestions(password)
        
        # Display results in columns
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Password Length", len(password))
        
        with col2:
            st.metric("Entropy", f"{entropy:.1f} bits")
        
        with col3:
            st.metric("Character Types", sum(analysis['composition'].values()))
        
        with col4:
            st.metric("Charset Size", analysis['charset_size'])
        
        # Strength indicator
        st.markdown("### Strength Assessment")
        
        if alert_type == "danger":
            st.error(f"{emoji} **{strength}** - This password is easily crackable!")
        elif alert_type == "warning":
            st.warning(f"{emoji} **{strength}** - This password needs improvement")
        elif alert_type == "info":
            st.info(f"{emoji} **{strength}** - This password is decent but could be better")
        else:
            st.success(f"{emoji} **{strength}** - Excellent password security!")
        
        # Visual strength meter
        strength_percentage = min(100, (entropy / 120) * 100)
        progress_color = {
            "danger": "#ff4444",
            "warning": "#ff8800", 
            "info": "#4488ff",
            "success": "#44ff44"
        }[alert_type]
        
        st.markdown(f"""
        <div style="background-color: #e0e0e0; border-radius: 10px; overflow: hidden;">
            <div style="width: {strength_percentage}%; height: 20px; background-color: {progress_color}; 
                        border-radius: 10px; transition: width 0.3s ease;"></div>
        </div>
        """, unsafe_allow_html=True)
        
        # Detailed analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Character Analysis")
            for char_type, present in analysis['composition'].items():
                status = "✅" if present else "❌"
                char_name = analyzer.character_sets[char_type]['name']
                st.write(f"{status} {char_name}")
            
            st.markdown(f"**Estimated crack time:** {crack_time}")
        
        with col2:
            st.markdown("### Improvement Suggestions")
            for suggestion in suggestions:
                st.write(suggestion)
        
        # Additional security info
        with st.expander("🔍 Advanced Analysis"):
            st.markdown("#### Security Metrics")
            st.write(f"- **Total possible combinations:** 2^{entropy:.1f} ≈ {2**entropy:.2e}")
            st.write(f"- **Character set size:** {analysis['charset_size']} characters")
            st.write(f"- **Entropy per character:** {entropy/len(password):.2f} bits")
            
            if analysis['missing_types']:
                st.markdown("#### Missing Character Types")
                for missing in analysis['missing_types']:
                    st.write(f"- {missing}")
            
            patterns = analyzer.check_common_patterns(password)
            if patterns:
                st.markdown("#### Detected Weak Patterns")
                for pattern in patterns:
                    st.write(f"- {pattern}")
    
    else:
        st.info("👆 Enter a password above to analyze its strength")
        
        # Educational content when no password is entered
        st.markdown("---")
        st.markdown("### What Makes a Strong Password?")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### ✅ Good Practices
            - Use 12+ characters
            - Mix uppercase and lowercase
            - Include numbers and symbols
            - Use unique passwords for each account
            - Consider passphrases
            """)
        
        with col2:
            st.markdown("""
            #### ❌ Avoid These
            - Common words or phrases
            - Personal information
            - Repeated characters (aaa, 111)
            - Sequential patterns (abc, 123)
            - Keyboard patterns (qwerty)
            """)


if __name__ == "__main__":
    main()