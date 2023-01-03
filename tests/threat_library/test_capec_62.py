from tmac import Model, ExternalEntity, Process, Technology, Protocol
from tmac.threat_library import CAPEC_62

threat = CAPEC_62()

def test_is_applicable(model: "Model") -> None:
    p = Process(model, "WebApp", technology = Technology.WEB_APPLICATION)
    
    p.out_of_scope = False    
    assert threat.is_applicable(p) == True

    p.out_of_scope = True
    assert threat.is_applicable(p) == False

def test_apply(model: "Model") -> None:
    e = ExternalEntity(model, "User", technology=Technology.BROWSER)
    p = Process(model, "WebApp", technology=Technology.WEB_APPLICATION)

    e.add_data_flow("WebTrafffic", destination=p, protocol=Protocol.HTTPS)
      
    risks = threat.apply(model=model, component=p)
    assert len(risks) == 1
    assert risks[0].text == "Cross-Site Request Forgery (CSRF) risk at WebApp via WebTrafffic from User"
