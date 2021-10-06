"""FlowStack module."""

class Flow:
    """Flow class."""

    DIR_INBOUND = 0
    DIR_OUTBOUND = 1

    def __init__(
        self,
        cookie: bytes,
        direction_allowed: bool,
        transport_allowed: bool,
        application_allowed: bool,
        direction: int
    ) -> None:
        """Construct a new Flow."""
        self.cookie = cookie
        self.direction_allowed = direction_allowed
        self.transport_allowed = transport_allowed
        self.application_allowed = application_allowed
        self.direction = direction

    def is_allowed(self) -> bool:
        """
        Return whether a Flow is allowed.

        None: undetermined
        False: not allowed
        True: allowed
        """
        if (
            self.direction_allowed and
            self.transport_allowed and
            self.application_allowed
        ):
            return True
        elif (
            self.direction_allowed is False or
            self.transport_allowed is False or
            self.application_allowed is False
        ):
            return False

        return None

    def dir_string(self) -> str:
        """Return a string representation of this flow's direction."""
        dir_string = 'Unknown'
        if self.direction == self.DIR_INBOUND:
            dir_string = 'Inbound'
        elif self.direction == self.DIR_OUTBOUND:
            dir_string = 'Outbound'
        return dir_string

    def __repr__(self) -> str:
        """Return a string representation of this Flow."""
        return (
            f'Flow with direction {self.dir_string()}. '
            f'Direction allowed: {self.direction_allowed}. '
            f'Transport allowed: {self.transport_allowed}, '
            f'Application port allowed: {self.application_allowed}'
        )

class FlowStack:
    """FlowStack class."""

    stack = {}
    cookies = []

    def __init__(self, max_size: int = 1024) -> None:
        """Construct a new FlowStack."""
        self.max_size = max_size

    def set_flow(
        self,
        cookie: bytes,
        direction_allowed: bool = None,
        transport_allowed: bool = None,
        application_allowed: bool = None,
        direction: int = None,
    ) -> Flow:
        """Push a new flow onto the stack or update an existing flow."""
        flow = self.get_flow(cookie)
        if flow is None:
            flow = Flow(
                cookie, direction_allowed, transport_allowed, application_allowed, direction
            )
            self.cookies.append(cookie)
        else:
            if direction_allowed is not None:
                flow.direction_allowed = direction_allowed
            if transport_allowed is not None:
                flow.transport_allowed = transport_allowed
            if application_allowed is not None:
                flow.application_allowed = application_allowed
            if direction is not None:
                flow.direction = direction

        self.stack[cookie] = flow
        self.trim_stack()
        return flow

    def get_flow(self, cookie: bytes) -> Flow:
        """Return the flow's status if it exists, None if it doesn't."""
        try:
            return self.stack[cookie]
        except KeyError:
            return None

    def trim_stack(self) -> None:
        """Drop the oldest flow to resize the stack to max size."""
        if len(self.stack) > self.max_size:
            self.stack.pop(self.cookies.pop(0))
