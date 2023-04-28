from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait


def take_screenshot(url, filename):
    # Set up Selenium webdriver
    options = webdriver.EdgeOptions()
    options.add_argument('--headless')
    driver = webdriver.Edge(options=options)
    driver.set_window_size(1800, 800)
    # Load webpage and take screenshot
    driver.get(url)
    wait = WebDriverWait(driver, 10)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "img")))
    driver.save_screenshot(filename)

    # Clean up
    driver.quit()
