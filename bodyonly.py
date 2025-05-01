from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel
from java.awt import BorderLayout
import re

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Body Only (Pretty JSON)")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return BodyOnlyTab(self.callbacks, controller, editable)

class BodyOnlyTab(IMessageEditorTab):
    def __init__(self, callbacks, controller, editable):
        self._editable = editable
        self._editor = callbacks.createMessageEditor(None, editable)
        self._panel = JPanel(BorderLayout())
        self._panel.add(self._editor.getComponent(), BorderLayout.CENTER)

    def getUiComponent(self):
        return self._panel

    def getTabCaption(self):
        return "Body Only"

    def isEnabled(self, content, isRequest):
        return content is not None and not isRequest

    def isModified(self):
        return self._editor.isMessageModified()

    def getMessage(self):
        return self._editor.getMessage()

    def setMessage(self, content, isRequest):
        if content is None or isRequest:
            self._editor.setMessage(None, False)
            return

        try:
            response_bytes = content.getResponse() if hasattr(content, 'getResponse') else content
            if response_bytes is None:
                self._editor.setMessage(None, False)
                return

            response_str = response_bytes.tostring()
            header_end = response_str.index("\r\n\r\n")
            headers = response_str[:header_end]
            body = response_str[header_end + 4:]

            body = re.sub(r"^for\s*\(;;\);", "", body)

            if body.strip().startswith("{") or body.strip().startswith("["):
                content_type = "application/json"
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-type:"):
                        content_type = line.split(":", 1)[1].strip()
                        break

                fake_headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: {}\r\n"
                    "Content-Length: {}\r\n\r\n"
                ).format(content_type, len(body.encode("utf-8")))
                fake_response = fake_headers + body
                self._editor.setMessage(fake_response.encode("utf-8"), False)
            else:
                self._editor.setMessage(None, False)
        except Exception:
            self._editor.setMessage(None, False)
