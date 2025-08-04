# FIT5238-SA11 Team Project**

## PROJECT LINK
`https://github.com/HaoLi104/FIT5238-SA11.git`

## QUICK START
1. **Install dependencies:** `pip install -r requirements.txt`
2. **Run locally:** `python app.py`
3. **Access:** Open browser to `http://localhost:5000`

## HOW TO USE
1. Enter any URL in the input field
2. Click "Start Detection"
3. View results: Green = Safe, Red = Risky
4. Use action buttons to proceed

## TEST CASES FOR MENTORS
- **Safe:** `https://www.google.com` (should show green shield)
- **Safe:** `https://www.amazon.com` (should show green shield)
- **Test:** `http://suspicious-site.com` (should show red warning)

## TECHNICAL DETAILS
- **Framework:** Flask web application
- **ML Model:** Gradient Boosting Classifier (30 features)
- **Model File:** `pickle/model.pkl`
- **Dependencies:** See requirements.txt

## TROUBLESHOOTING
- **Module errors:** Run `pip install -r requirements.txt`
- **Port issues:** Change port in app.py if needed
- **Model errors:** Ensure pickle/model.pkl exists

## FILE STRUCTURE
```
├── app.py (main application)
├── feature.py (feature extraction)
├── pickle/model.pkl (ML model)
├── templates/index.html (UI)
├── static/styles.css (styling)
└── requirements.txt (dependencies)
```
